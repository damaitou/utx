
use std::io::{Write};
use std::fs::File;
use xxhash_rust::xxh3::Xxh3;
use std::net::{SocketAddr, UdpSocket, IpAddr, TcpStream};
use std::os::raw::{c_void, c_char, c_int};
use std::os::unix::io::AsRawFd;
use std::ffi::CStr;
use log::{error, warn, info, debug, trace};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time::{Duration, Instant};

mod agent_def;
use crate::agent_def::Header;

#[link(name = "utx", kind = "static")]
extern "C" {
    fn bind_socket_to_interface(
        s: c_int,
        if_name: *const u8, 
    ) -> c_int;
}

#[macro_use]
extern crate lazy_static;

use mylib::config::{self, ClientSetting, TxConfig, TxFileChannelConfig, TxDatagramChannelConfig, INVALID_INDEX, ChannelMode};
use mylib::utx::{self, UtxReceiver};
use mylib::errors::*;
use mylib::audit;
use mylib::util;
use mylib::context::{self, ThreadAction, ThreadMsg};
use mylib::ftp;

const PROG_NAME: &'static str = "es";

const BLOC_MODE_NONE: u8 = 0;
const BLOC_MODE_FTP: u8 = 1;
const BLOC_MODE_UDP: u8 = 2;

/*
#[derive(Copy, Clone)]
struct UtxBuf {
    channel: u8,
    size: usize,
    data: [u8;64*1024],
}
*/

struct UtxHeader {
    _utx_type: u8,
    channel: u8,
    seq: u16,
    head: u8,
    tail: u8,
    _check: u16,
    packet_opt: u8,
    packet_head: u8,
    packet_tail: u8,
    payload: *mut u8,
    payload_size: usize,
}

#[repr(C)]
struct FileHeader {
    fileattr: u16,
    filesize: u64,
    md5sum: [u8; 33],
    filename: [u8; 256],
    username: [u8; 65],
}

impl FileHeader {
    /*
    fn file_size(&self) -> u64 {
        return self.filesize;
    }
    */

    fn file_name(&self) -> String {
        let ptr = &self.filename[0] as *const _ as *const c_char;
        let cs = unsafe { CStr::from_ptr(ptr) };
        cs.to_string_lossy().into_owned()
    }
}

const UDP_EMPTY:u32 = 1;
const UDP_FILLING:u32 = 2;
const UDP_READY:u32 = 3;
const UDP_ERROR:u32 = 4;

struct AgentRuntime {
    fcc: TxFileChannelConfig, //for agent
    tcp_socket: Option<TcpStream>, //for agent
    tcp_socket_handle: Option<thread::JoinHandle<Result<TcpStream>>>,
    connector_flag: Arc<AtomicU8>, //to indicate whether connector job has been done
}

impl AgentRuntime {
    fn new(fcc: config::TxFileChannelConfig) -> Result<AgentRuntime> {
        let cs = match &fcc.mode {
            ChannelMode::ClientPushAgent(cs) => cs,
            _ => { return Err("expect 'client_push_agent' but got something else".into()) },
        };

        let (connector_flag, handle) = AgentRuntime::spawn_an_agent_thread(&cs, 0, None)?; //todo
        Ok(AgentRuntime {
            fcc: fcc,
            tcp_socket: None,
            tcp_socket_handle: Some(handle),
            connector_flag: connector_flag,
        })
    }

    fn agent_packet_ready(&mut self, data: &[u8]) -> Result<()> {
        if let Some(tcp) = self.tcp_socket.as_mut() {
            tcp.write_all(data)
                .map_err(|e|{ self.tcp_socket = None; e })?; //drop the tcp_socket if error
        } else if self.tcp_socket_handle.is_some() {
            if self.connector_flag.load(Ordering::SeqCst) == WORKER_FLAG_DONE {
                let mut tcp = self
                    .tcp_socket_handle
                    .take() //which makes the tcp_socket_handle None
                    .unwrap()
                    .join()
                    .map_err(|e|format!("join error:{:?}",e))?
                    .map_err(|e|format!("connect to peer failed:{:?}",e))?;
                tcp.write_all(data)?;
                self.tcp_socket = Some(tcp);
            } else {
                //tcp_socket not established yet,
                warn!("无法发送AGENT报文:未与对端agent建立连接"); //todo
            }
        } else {
            if let ChannelMode::ClientPushAgent(cs) = &self.fcc.mode {
                let (connector_flag, handle) = AgentRuntime::spawn_an_agent_thread(&cs, 0, Some(data))?;
                self.connector_flag = connector_flag;
                self.tcp_socket_handle = Some(handle);
            }
        }

        Ok(())
    }

    fn spawn_an_agent_thread(
        cs: &ClientSetting,
        fails_before: usize,
        data: Option<&[u8]>,
    ) -> Result<(Arc<AtomicU8>, thread::JoinHandle<Result<TcpStream>>)> {
        if fails_before != 0 {
            //sleep 2*failes_before seconds for each failure, 30 seconds max
            thread::sleep(Duration::from_secs(std::cmp::min(2*fails_before, 30) as u64));
        }
        let connector_flag = Arc::new(AtomicU8::new(WORKER_FLAG_NONE));
        let t_connector_flag = connector_flag.clone();
        let t_cs = cs.clone();
        let t_data = data.map(|data|data.to_vec());
        let handle = thread::spawn(move|| {
            let mut tcp_stream = util::create_bound_tcp_stream(&t_cs.bind_interface, &t_cs.remote_ftp_host_address)?;
            let mut header = Header::new();
            header.request_for_read(&mut tcp_stream)?;
            if let Some(t_data) = t_data {
                tcp_stream.write_all(&t_data[..])?;
                //tcp_stream.write_all(t_data.as_mut_slice())?;
            }
            t_connector_flag.store(WORKER_FLAG_DONE, Ordering::SeqCst);
            Ok(tcp_stream)
        });

        Ok((connector_flag, handle))
    }
}

struct DatagramRuntime {
    is_agent: bool, //false = udp, true = agent
    channel: usize,
    vchannel: i64,
    audit: bool,
    peer_addr: SocketAddr,
    agent_rt: Option<AgentRuntime>, //for agent
    udp_socket: Option<UdpSocket>, //for udp
    udp: [u8;64*1024],
    udp_len: usize,
    udp_status: u32,
    utx_seq: i32,
    utx_lost: u32,
    //running status
    status: usize,
    //traffic statistics
    traffic_in: u64,
    traffic_out: u64,
    traffic_packets: u64,
    //time counting
    last_audit_time: Instant,
}

impl DatagramRuntime {

    fn new_from_fcc(fcc: config::TxFileChannelConfig) -> Result<DatagramRuntime> {
        let addr  = match &fcc.mode {
            ChannelMode::ClientPushAgent(cs) => cs.remote_ftp_host_address.parse().chain_err(||"invalid remote_ftp_host_address.parse")?,
            _ => { return Err("expect 'client_push_agent' but got something else".into()) },
        };

        let drt = DatagramRuntime {
            is_agent: true, //AGENT
            channel: fcc.channel,
            vchannel: fcc.vchannel,
            audit: fcc.audit,
            peer_addr: addr,
            agent_rt: Some(AgentRuntime::new(fcc)?),
            udp_socket: None,
            udp: [0 as u8; 64*1024],
            udp_len: 0,
            udp_status: UDP_EMPTY,
            utx_seq: -1,
            utx_lost: 0,
            status: context::RUNNING,
            traffic_in: 0,
            traffic_out: 0,
            traffic_packets: 0,
            last_audit_time: Instant::now().checked_sub(Duration::from_secs(10)).unwrap(), //10 seconds before now
        };

        Ok(drt)
    }

    fn new_from_dcc(dcc:TxDatagramChannelConfig) -> Result<DatagramRuntime> {
        let ipaddr: IpAddr = dcc.host.parse().chain_err(||"IP地址无法解释")?;
        let addr = SocketAddr::new(ipaddr, dcc.port);
        let socket = UdpSocket::bind("[::]:0").chain_err(||"绑定UDP地址失败")?;

        if dcc.bind_interface.len() != 0 {
            let mut c_interface = dcc.bind_interface.clone();
            c_interface.push('\0');
            let fd = socket.as_raw_fd();
            match unsafe { bind_socket_to_interface(fd, c_interface.as_ptr()) } {
                0 => {},
                _ => {
                    error!("报文通道{}:bind_socket_to_interface('{}') failed.", dcc.channel, dcc.bind_interface);
                    return None.ok_or(
                        ErrorKind::UnrecoverableError(line!(),format!("绑定网卡'{}'失败",dcc.bind_interface)))?;
                },
            }
        }

        if let Some(sndbuf_size) = dcc.sndbuf_size.as_ref() {
            if !util::set_so_sndbufforce(socket.as_raw_fd(), *sndbuf_size) { 
                warn!("set_so_sndbufforce for datagram channel {} failed", dcc.channel);
            }
        }

        let drt = DatagramRuntime {
            is_agent: false, //UDP
            channel: dcc.channel,
            vchannel: dcc.vchannel,
            audit: dcc.audit,
            /*
            fcc: None,
            dcc: Some(dcc),
            */
            peer_addr: addr,
            //tcp_socket: None,
            agent_rt: None,
            udp_socket: Some(socket),
            udp: [0 as u8; 64*1024],
            udp_len: 0,
            udp_status: UDP_EMPTY,
            utx_seq: -1,
            utx_lost: 0,
            status: context::RUNNING,
            traffic_in: 0,
            traffic_out: 0,
            traffic_packets: 0,
            last_audit_time: Instant::now().checked_sub(Duration::from_secs(10)).unwrap(), //10 seconds before now
        };

        Ok(drt)
    }

    fn packet_ready(&mut self) -> Result<()> {
        if let Some(udp) = self.udp_socket.as_mut() {
            udp.send_to(&self.udp[0..self.udp_len], &self.peer_addr)?;
        }
        else if let Some(agent_rt) = self.agent_rt.as_mut() {
            agent_rt.agent_packet_ready(&self.udp[0..self.udp_len])?;
        }

        self.traffic_packets += 1;
        self.traffic_out += self.udp_len as u64;
        self.reset();
        Ok(())
    }

    fn reset(&mut self) {
        self.udp_len = 0;
        self.udp_status = UDP_EMPTY;
        self.utx_lost = 0;
    }

    fn audit_d(
        &mut self, 
        result:u32,
        result_msg:String, 
        traffic_in:i64, 
        traffic_out:i64,
    ) {
        if !self.audit {
            return;
        }
        //为避免信息过多,UDP错误告警信息10秒以上才记录一次
        if result == audit::AR_OK || self.last_audit_time.elapsed().as_secs() >= 10 {
            let time = time::get_time();
            let dar = audit::DatagramAuditRecord {
                time_sec: time.sec,
                time_nsec: time.nsec,
                side: audit::AS_RX,
                channel: self.channel as u8,
                vchannel: self.vchannel,
                event: audit::AE_FERRY,
                result: result,
                result_msg: result_msg,
                ip: format!("{}", self.peer_addr.ip()),
                traffic_in: traffic_in,
                traffic_out: traffic_out,
                interval: config::FLOW_STATISTICS_INTERVAL,
            };
            audit::audit_d(&dar);
            self.last_audit_time = Instant::now();
        }
    }
}

#[derive(Debug)]
struct BlocStream {
    c_stream: TcpStream,
    d_stream: TcpStream,
}

#[derive(Debug)]
struct BlocUdp {
    peer_addr: SocketAddr,
    socket: UdpSocket,
}

#[derive(Debug)]
struct BlocWorker {
    worker_handle: Option<thread::JoinHandle<Result<BlocStream>>>,
    worker_flag: Arc<AtomicU8>, //to indicate whether job has been done
}
//for worker_flag
const WORKER_FLAG_NONE: u8 = 0;
const WORKER_FLAG_DONE: u8 = 1; //worker_thread has finished and created a BlocStream

impl BlocWorker {
    fn is_done(&self) -> bool {
        self.worker_handle.is_some() && 
        self.worker_flag.load(Ordering::SeqCst) == WORKER_FLAG_DONE 
    }

    fn join(&mut self) -> Result<BlocStream> {
        match self.worker_handle.take().unwrap().join() {
            Err(e) => {
                let msg = format!("BlocWorker join() error:{:?}", e);
                None.ok_or(msg)?
            }
            Ok(val) => val,
        }
    }
}

struct BlocFtp {
    //bloc_stream:与对端ftp服务器的两个TCP连接(命令通道和数据通道)
    bloc_stream: Option<BlocStream>,
    //worker:用于建立ftp连接的线程,连接建立后即释放
    worker: Option<BlocWorker>,
    //记录连接成功前的失败次数,用于频度控制
    fails: usize,
}

impl BlocFtp {

    fn send_bloc(&mut self, buf: &[u8], send_length: bool) -> Result<()> {
        let _bs = self.bloc_stream.as_mut()
            .ok_or("send_bloc() bloc_stream is empty")?;

        if send_length {
            let buf_len = format!("{:05}", buf.len());
            self.bloc_stream.as_mut().unwrap().d_stream.write(buf_len.as_bytes()).chain_err(||{
                self.bloc_stream = None;
                "send_bloc() sending bloc data error"
            })?;
        }

        self.bloc_stream.as_mut().unwrap().d_stream.write(buf).chain_err(||{
            self.bloc_stream = None;
            "send_bloc() sending bloc data error"
        })?;
        Ok(())
    }
}

struct BlocPacket {
    data: [u8;64*1024],
    data_len: usize,
    data_status: u32,
    utx_seq: i32,
    utx_lost: u32,
    _packet_opt: u8,
}
const PACKET_EMPTY:u32 = 1;
const PACKET_FILLING:u32 = 2;
const PACKET_READY:u32 = 3;
const PACKET_ERROR:u32 = 4;

impl BlocPacket {
    fn new() -> BlocPacket {
        BlocPacket {
            data: [0 as u8; 64*1024],
            data_len: 0,
            data_status: PACKET_EMPTY,
            utx_seq: -1,
            utx_lost: 0,
            _packet_opt: 0,
        }
    }

    fn reset(&mut self) {
        self.data_len = 0;
        self.data_status = PACKET_EMPTY;
        self.utx_lost = 0;
    }

    /*
     *组装BlocPacket.返回值tuple中的第二值指示组装是否完成
     *  --对于STREAM模式,收到一个utx包即可成为一个BlocPacket;
     *  --对于DATAGRAM模式,调用assemble_packet2完成实际组装;
     */
    fn assemble_packet(&mut self, utx: &UtxHeader) -> (&[u8], bool) {
        let (buf, ready) = match utx.packet_opt {
            utx::UTX_OPT_STREAM => {
                let offset = if utx.head != 0 { std::mem::size_of::<FileHeader>() } else { 0 };
                let payload = unsafe {std::slice::from_raw_parts(utx.payload, utx.payload_size)};
                (&payload[offset..], true)
            }
            utx::UTX_OPT_DATAGRAM => {
                self.assemble_packet2(utx);
                (&self.data[..self.data_len], self.data_status == PACKET_READY)
            }
            _ => unreachable!(),
        };
        (buf, ready)
    }

    /*
     *根据utxhdr_t中的packet_head/packet_tail信息组装DATAGRAM模式的BlocPacket
     */
    fn assemble_packet2(&mut self, utx: &UtxHeader) {
        let offset = if utx.head != 0 { std::mem::size_of::<FileHeader>() } else { 0 };
        let payload = unsafe {std::slice::from_raw_parts(utx.payload, utx.payload_size)};
        let payload = &payload[offset..];

        if utx.packet_head != 0 {
            if self.data_status != PACKET_EMPTY && self.data_status != PACKET_READY {
                warn!("文件通道{},上一个Block没有正常结束(缺少tail包)", utx.channel);
                self.reset();
            }

            self.data[0..payload.len()].copy_from_slice(&payload);
            self.data_len = payload.len();
            self.data_status = if utx.packet_tail != 0 { PACKET_READY } else { PACKET_FILLING };
        } 
        else if self.data_status == PACKET_FILLING {
            let diff = seqdiff(utx.seq as i32, self.utx_seq);
            if self.utx_seq != -1 && diff != 1 {
                warn!("文件通道{}丢失{}个数据包:seq从{}跳到{}.放弃当前Block",
                    utx.channel, diff, self.utx_seq, utx.seq);
                self.data_status = PACKET_ERROR;
                self.utx_lost += (diff-1) as u32;
            }
            else {
                if self.data_len + payload.len() > 64*1024 {
                    error!("文件通道{}严重错误:当前Block长度超过64k,请检查发送端程序", utx.channel);
                    self.data_status = PACKET_ERROR;
                } 
                else {
                    self.data[self.data_len..self.data_len+payload.len()]
                        .copy_from_slice(&payload);
                    self.data_len += payload.len();
                    self.data_status = if utx.packet_tail != 0 { UDP_READY } else { UDP_FILLING }; 
                }
            }
        }
        else {
            warn!("文件通道{}丢弃当前数据包,因为当前Block状态已标记为错误/空", utx.channel);
        }
        self.utx_seq = utx.seq as i32;
    }
}

struct BlocFile {
    bloc_name: String,
    bloc_seq: u32,
    bloc_left: usize,
    bloc_file: Option<File>,
}

impl BlocFile {
    fn new(name: &str) -> BlocFile {
        let bf = BlocFile {
            bloc_name: String::from(name),
            bloc_seq: 0,
            bloc_left: 0,
            bloc_file: None,
        };
        bf
    }

    fn write_bloc(&mut self, buf: &[u8]) -> Result<()> {
        if self.bloc_file.is_none() {
            let bloc_file = format!("{}-{:04}", self.bloc_name, self.bloc_seq); 
            let f = util::ensure_file(&bloc_file, Some(50))
                .chain_err(||format!("文件通道无法创建BLOC文件{}", bloc_file))?;
            self.bloc_left = 1024*1024*10;
            self.bloc_file = Some(f);
        }

        match &mut self.bloc_file {
            None => {
                warn!("OOPS!!!bloc_file is None, should not happen!");
            }
            Some(file) => {
                if buf.len() < self.bloc_left {
                    file.write(buf).chain_err(||"文件通道写BLOC文件失败")?;
                    self.bloc_left -= buf.len();
                }
                else {
                    let nwrite = self.bloc_left;
                    file.write(&buf[..nwrite]).chain_err(||"文件通道写BLOC文件失败")?;
                    self.bloc_file = None;
                    self.bloc_seq = (self.bloc_seq + 1) % 1000;
                    if buf.len() > nwrite {
                        self.write_bloc(&buf[nwrite..])?;
                    }
                }
            }
        }

        Ok(())
    }
}

/*
enum BlocMode {
    None,
    Udp(BlocUdp),
    Ftp(BlocFtp),
}
*/

struct BlocRuntime {
    file: BlocFile,
    packet: BlocPacket,
    udp: Option<BlocUdp>, //BLOC_MODE_UDP
    ftp: Option<BlocFtp>, //BLOC_MODE_FTP
}

fn bloc_worker_thread_handler(
    _channel: usize, 
    _vchannel: i64, 
    fcc: &TxFileChannelConfig, 
    cs: &ClientSetting, 
    bloc_name: &str, 
    fails_before: usize, //how many fails before this try
) -> Result<BlocStream> {

    if fails_before != 0 {
        //sleep 2*failes_before seconds for each failure, 30 seconds max
        thread::sleep(Duration::from_secs(2*std::cmp::min(fails_before, 15) as u64));
    }

    let mut ftp = ftp::FtpStream::new("/home/rx", 0, &fcc, &cs, bloc_name, false)?; //todo:: is utx_root="/home/rx" ok?
    let d_stream = ftp.ftp_passive()?;
    ftp.say(format!("NATR {}\r\n", bloc_name).as_str())?;
    if !ftp.expect("150")? { 
        None.ok_or("NATR command failed")?;
    }

    let bs = BlocStream {
        c_stream: ftp.c_stream_only(),
        d_stream: d_stream,
    };

    Ok(bs)
}

impl BlocRuntime {

    fn spawn_a_bloc_worker(
        fcc: &TxFileChannelConfig,
        cs: &ClientSetting,
        name: &str,
        fails_before: usize,
    ) -> Result<BlocWorker> {
        let thread_fcc = fcc.clone();
        let thread_cs = cs.clone();
        let bloc_name = name.to_string().clone();
        let worker_flag = Arc::new(AtomicU8::new(WORKER_FLAG_NONE));
        let thread_worker_flag = worker_flag.clone();
        let thread_channel = fcc.channel;
        let thread_vchannel = fcc.vchannel;

        let handle = thread::spawn(move|| {
            let result = bloc_worker_thread_handler(
                thread_channel, 
                thread_vchannel, 
                &thread_fcc,
                &thread_cs, 
                &bloc_name, 
                fails_before,
            );
            thread_worker_flag.store(WORKER_FLAG_DONE, Ordering::SeqCst);
            result
        });

        let worker = BlocWorker {
            worker_handle: Some(handle),
            worker_flag: worker_flag,
        };

        Ok(worker)
    }

    fn new(name: &str, mode: u8, fcc: &TxFileChannelConfig) -> Result<BlocRuntime> {

        let mut bloc = BlocRuntime {
            file: BlocFile::new(name),
            packet: BlocPacket::new(),
            udp: None,
            ftp: None,
        };

        if mode == BLOC_MODE_FTP {
            //let worker = match fcc.client_setting.as_ref() {
            let worker = match &fcc.mode {
                ChannelMode::ClientPush(cs)|ChannelMode::ClientPull(cs) => Some(BlocRuntime::spawn_a_bloc_worker(&fcc, &cs, name, 0)?),
                _ => None, //should not happen
            };
            let ftp = BlocFtp {
                bloc_stream: None,
                worker: worker,
                fails: 0,
            };
            bloc.ftp = Some(ftp);
        } else {
            let ipaddr: IpAddr = fcc.relay_ip.parse().chain_err(||"IP地址无法解释")?;
            let addr = SocketAddr::new(ipaddr, fcc.relay_port);
            let socket = UdpSocket::bind("[::]:0").chain_err(||"绑定UDP地址失败")?;
            let udp = BlocUdp {
                peer_addr: addr,
                socket: socket,
            };
            bloc.udp = Some(udp);
        }

        Ok(bloc)
    }

    fn process_bloc_with_ftp(&mut self, utx: &UtxHeader, fcc: &TxFileChannelConfig) -> Result<()> {
        let (buf, ready) = self.packet.assemble_packet(utx);
        trace!("assemble_packet(), buf.len()={}, ready={}", buf.len(), ready);
        if !ready {
            return Ok(())
        }

        self.file.write_bloc(buf)?;
        if self.ftp.is_none() {
            warn!("process_bloc_with_ftp(), ftp is empty");
            return Ok(()); 
        }

        let send_length = utx.packet_opt == utx::UTX_OPT_DATAGRAM;
        let ftp = self.ftp.as_mut().unwrap();
        match &mut ftp.bloc_stream {
            Some(_bs) => {
                //ftp connection established, send out bloc data
                ftp.send_bloc(buf, send_length)?;
                self.packet.reset();
            }
            None => {
                match &mut ftp.worker {
                    //worker is connecting bloc ftp
                    Some(worker) => {
                        if worker.is_done() {
                            /* when connecting job done, we
                             * 1. obtain the ftp connection to 'ftp.bloc_stream',
                             * 2. consume 'ftp.worker' and make it None (join the worker thread)
                             * 3. send out the bloc data
                             */
                            ftp.bloc_stream = 
                                Some(ftp.worker.take().unwrap().join()
                                    .map_err(|e|{
                                        ftp.fails += 1;
                                        e
                                    })
                                    .map(|v|{
                                        ftp.fails = 0;
                                        v
                                    })?
                                );
                            ftp.send_bloc(buf, send_length)?;
                            self.packet.reset();
                        } else {
                            //connecting job not done yet
                        }
                    }
                    //there is no worker connecting bloc ftp
                    None => {
                        //match fcc.client_setting.as_ref() {
                        match &fcc.mode {
                            ChannelMode::ClientPush(cs) | ChannelMode::ClientPull(cs) => {
                                //spawn a worker to connect bloc ftp, and push back the bloc data
                                //todo:: if ftp.fails too many times, should we try no more?
                                warn!("no ftp connection available, spawning a worker to connect...");
                                let worker = BlocRuntime::spawn_a_bloc_worker(&fcc, &cs, &self.file.bloc_name, ftp.fails)?;
                                ftp.worker = Some(worker);
                            }
                            _ => {} //should not happen
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn process_bloc_with_udp(&mut self, utx: &UtxHeader) -> Result<()> {
        let (buf, ready) = self.packet.assemble_packet(utx);
        if !ready {
            return Ok(())
        }

        self.file.write_bloc(buf)?;
        match &self.udp {
            None => {}
            Some(udp) => {
                udp.socket.send_to(buf, &udp.peer_addr)
                    .chain_err(||format!("文件通道转发BLOC失败"))?;
            }
        }
        Ok(())
    }
}

struct FileRuntime {
    fcc: TxFileChannelConfig,
    file_name: Option<String>,
    file:  Option<File>,
    file_size: u64,
    utx_seq: i32,
    utx_lost: u32, //how many packet lost during a file ferry
    bloc_mode: u8, //BLOC_MODE_UDP or BLOC_MODE_FTP
    bloc: Option<BlocRuntime>,
    status: usize, //runtime status
    //data_cache
    cache: Vec<u8>,
    cache_len: usize, //how many bytes stored in cache
    //xxh3 hasher for file integrity check
    hasher: Option<Xxh3>,
    file_hash: Option<String>,
}

impl FileRuntime {

    fn new(fcc: TxFileChannelConfig) -> Result<FileRuntime> {

        let path = fcc.local_root_path.as_str();
        std::fs::create_dir_all(path).
            chain_err(||format!("ensure_path()创建目录{}失败",path))?;

        let bloc_mode;
        if !fcc.relay_ip.is_empty() && fcc.relay_port != 0 {
            bloc_mode = BLOC_MODE_UDP;
        } else {
            bloc_mode = match fcc.mode {
                ChannelMode::ClientPush(_) | ChannelMode::ClientPull(_) => BLOC_MODE_FTP,
                _ => BLOC_MODE_NONE,
            }
        }

        let frt = FileRuntime {
            fcc: fcc,
            file_name: None,
            file: None,
            file_size: 0,
            utx_seq: -1,
            utx_lost: 0,
            bloc_mode: bloc_mode,
            bloc: None,
            status: context::RUNNING,
            cache: vec![0;1024*1024],
            cache_len: 0,
            hasher: None,
            file_hash: None,
        };

        Ok(frt)
    }

    fn flush_file_cache(&mut self) -> Result<()> {
        self.file.as_ref().unwrap().write(&self.cache[..self.cache_len])
            .chain_err(||format!("通道{}写文件失败", self.fcc.channel))?;
        self.file_size += self.cache_len as u64;
        self.cache_len = 0;
        Ok(())
    }

    fn append_file_cache(&mut self, data: &[u8]) -> Result<()> {
        if self.cache_len + data.len() > 1024*1024 {
            self.flush_file_cache()?;
        }
        self.cache[self.cache_len..self.cache_len+data.len()].copy_from_slice(data);
        self.cache_len += data.len();
        Ok(())
    }

    fn reset_and_finishe_normally(&mut self) {
        if let Some(rel_file) = &self.file_name {
            self.file = None;
            match std::fs::rename(
                format!("{}/{}.uploading", self.fcc.local_root_path, rel_file),
                format!("{}/{}", self.fcc.local_root_path, rel_file),
            ) {
                Err(e) => {
                    self.audit_f(audit::AR_ERROR, audit::AE_FERRY, format!("重命名文件失败:{:?}",e));
                    error!("rename() file '{}/{}.uploading' failed:{:?}", self.fcc.local_root_path, rel_file, e)
                },
                Ok(_) => {
                    match self.fcc.mode {
                        ChannelMode::Internal(_) | ChannelMode::Server(_) => self.audit_f(audit::AR_OK, audit::AE_FERRY, "ok".to_string()),
                        _ => {},
                    }
                }
            }
        }
        self.file = None;
        self.file_name = None;
        self.file_size = 0;
        self.utx_lost = 0;
        self.cache_len = 0;
        self.hasher = None;
        self.file_hash = None;
    }

    fn reset_and_cleanup_unfinished_file(&mut self, has_tail_packet:bool) {
        if let Some(rel_file) = &self.file_name {
            let err_msg = match has_tail_packet {
                true => format!("丢失{}个数据包/xxh3摘要(哈希值)校验失败", self.utx_lost),
                false => format!("丢失文件尾包,至少丢失{}个数据包/无法校验xxh3摘要(哈希值)",self.utx_lost+1),
            };
            warn!("文件通道{},文件'{}':{}", self.fcc.channel, rel_file, err_msg);
            self.audit_f(
                audit::AR_ERROR, 
                audit::AE_LOST_PACKET, 
                err_msg,
            ); 
            self.file = None;
            if let Err(e) = std::fs::remove_file(format!("{}/{}.uploading", self.fcc.local_root_path, rel_file)) {
                error!("remove_file() file '{}/{}.uploading' failed:{:?}", self.fcc.local_root_path, rel_file, e);
            }
        }
        self.file = None;
        self.file_name = None;
        self.file_size = 0;
        self.utx_lost = 0;
        self.cache_len = 0;
    }

    fn audit_f(&self, event:u32, result:u32, result_msg:String,) {
        if !self.fcc.audit || self.file_name.is_none() {
            return;
        }
        let time = time::get_time();
        /*
        let (ip, user) = match self.fcc.client_setting.as_ref() {
            Some(cs) => (cs.remote_ftp_host_address.as_str(), cs.remote_ftp_user.as_str()),
            None => ("",""),
        };
        */
        let (ip, user) = match &self.fcc.mode {
            ChannelMode::ClientPush(cs) | ChannelMode::ClientPull(cs) => (cs.remote_ftp_host_address.as_str(), cs.remote_ftp_user.as_str()),
            _ => ("",""),
        };
        let far = audit::FileAuditRecord {
            time_sec: time.sec,
            time_nsec: time.nsec,
            side: audit::AS_RX,
            channel: self.fcc.channel as u8,
            vchannel: self.fcc.vchannel,
            event: event,
            result: result,
            result_msg: result_msg,
            ip: ip.to_string(),
            user: user.to_string(),
            file: self.file_name.as_ref().unwrap().clone(),
            file_size: self.file_size as i64,
        };
        audit::audit_f(&far);
    }
}

fn decode(req: &str) -> (&str, u32) {
    let vs: Vec<&str> = req.split(' ').collect();
    if vs.len() != 2 {
        return ("invalid", 0);
    }

    match vs[1].parse() {
        Ok(val) => (vs[0], val),
        Err(_) => ("invalid", 0),
    }
}

#[repr(C)]
struct UtxRuntime {
    pp: &'static util::ProgParam,
    config: TxConfig,
    drts: Vec<DatagramRuntime>, //datagram(udp) channel runtime
    adrts: Vec<DatagramRuntime>, //datagram(agent) channel runtime
    frts: Vec<FileRuntime>,     //file channel runtime
    channel_to_drt_index: [usize; 256],
    channel_to_adrt_index: [usize; 256],
    channel_to_frt_index: [usize; 256],
    tx: Sender<(String, String)>,
}

fn seqdiff(this_seq: i32, last_seq: i32) -> i32 {
    let mut diff = this_seq - last_seq;
    if diff < 0 {
        diff += 1<<16;
    }
    diff
}

impl Drop for UtxRuntime {
    fn drop(&mut self) {
        trace!("UtxRuntime being dropped...");
    }
}

impl UtxRuntime {

    fn ctrl_report(&self, code: &str, info: &str) {
        if let Err(e) = self.tx.send((code.to_string(), info.to_string())) {
            error!("Sender::send() error, code={},info={},error={:?}", code, info, e);
            std::process::exit(-1);
        }
    }

    fn reload_config(&mut self) {
        eprintln!("reloading config..."); 
        self.config = util::load_config(&self.pp, true, true, false);
    }

    #[inline]
    fn get_adrt(&mut self, channel: u8) -> Option<&mut DatagramRuntime> {
        let index = self.channel_to_adrt_index[channel as usize];
        match index {
            INVALID_INDEX => None,
            index => Some(&mut self.adrts[index]),
        }
    }

    #[inline]
    fn get_drt(&mut self, channel: u8) -> Option<&mut DatagramRuntime> {
        let index = self.channel_to_drt_index[channel as usize];
        match index {
            INVALID_INDEX => None,
            index => Some(&mut self.drts[index]),
        }
    }

    #[inline]
    fn get_frt(&mut self, channel: u8) -> Option<&mut FileRuntime> {
        let index = self.channel_to_frt_index[channel as usize];
        match index {
            INVALID_INDEX => None,
            index => Some(&mut self.frts[index]),
        }
    }

    fn set_drt(&mut self, channel: u8, drt:DatagramRuntime) {
        let index = self.channel_to_drt_index[channel as usize];
        match index {
            INVALID_INDEX => {
                self.channel_to_drt_index[channel as usize] = self.drts.len();
                self.drts.push(drt);
            }
            index => {
                self.drts[index] = drt;
            }
        }
     }

    fn set_frt(&mut self, channel: u8, frt:FileRuntime) {
        let index = self.channel_to_frt_index[channel as usize];
        match index {
            INVALID_INDEX => {
                self.channel_to_frt_index[channel as usize] = self.frts.len();
                self.frts.push(frt);
            }
            index => {
                self.frts[index] = frt;
            }
        }
    }

    fn on_datagram(&mut self, utx: &UtxHeader) -> Result<()> {
        let drt = 
            if utx._utx_type == utx::UTX_TYPE_DATAGRAM {
                self.get_drt(utx.channel).ok_or(format!("报文通道{}没有配置,请检查配置文件", utx.channel))?
            } else {
                self.get_adrt(utx.channel).ok_or(format!("AGENT通道{}没有配置,请检查配置文件", utx.channel))?
            };

        /*
        //if std::intrinsics::unlikely(drt.status != context::RUNNING) {
        if drt.status != context::RUNNING {
            //silentyly drop the packet
            return Ok(()); 
        }
        */

        drt.traffic_in += utx.payload_size as u64;

        if utx.head != 0 {
            if drt.udp_status != UDP_EMPTY { //todo:: what if last-uddp is UDP_ERROR?
                warn!("报文通道{},上一个报文没有正常结束(no tail packet or UDP_ERROR)", utx.channel);
                drt.reset();
            }

            drt.udp[0..utx.payload_size].copy_from_slice(unsafe{
                std::slice::from_raw_parts(utx.payload, utx.payload_size)
            });
            drt.udp_len = utx.payload_size;
            drt.udp_status = if utx.tail != 0 { UDP_READY } else { UDP_FILLING };
        }
        else if drt.udp_status == UDP_FILLING {
            let diff = seqdiff(utx.seq as i32, drt.utx_seq);
            if drt.utx_seq != -1 && diff != 1 {
                warn!("报文通道{}丢失{}个数据包:seq从{}跳到{}.放弃当前报文", 
                    utx.channel, diff-1, drt.utx_seq, utx.seq);
                drt.udp_status = UDP_ERROR;
                drt.utx_lost += (diff-1) as u32;
                if drt.audit {
                    drt.audit_d(
                        audit::AR_ERROR, 
                        format!("从{}跳到{},丢失{}个数据包",drt.utx_seq, utx.seq, diff-1),
                        0,
                        0,
                    );
                }
            }
            else {
                if drt.udp_len + utx.payload_size > 64*1024 {
                    error!("报文通道{}严重错误:当前报文长度超过64k,请检查发送端程序", utx.channel);
                    drt.udp_status = UDP_ERROR;
                }
                else {
                    drt.udp[drt.udp_len..drt.udp_len+utx.payload_size].copy_from_slice(unsafe{
                        std::slice::from_raw_parts(utx.payload, utx.payload_size)
                    });
                    drt.udp_len += utx.payload_size;
                    drt.udp_status = if utx.tail != 0 { UDP_READY } else { UDP_FILLING };
                }
            }
        }
        else {
            warn!("报文通道{}丢弃当前数据包,因为当前报文状态已标记为错误/空", utx.channel);
        }
        drt.utx_seq = utx.seq as i32;
        //drt.traffic_in += utx.payload_size as u64;

        if drt.udp_status == UDP_READY {
            drt.packet_ready()
                .map_err(|e|{
                    drt.reset(); 
                    format!("报文通道{}发送UDP/AGENT报文失败:{:?}", drt.channel, e)
                })?;
            /*
               drt.socket.send_to(&drt.udp[0..drt.udp_len], &drt.peer_addr)
               .map(|_|{
               drt.traffic_packets += 1;
               drt.traffic_out += drt.udp_len as u64;
               drt.reset();
               })
               .chain_err(||{
               drt.reset();
               format!("报文通道{}发送UDP报文失败", utx.channel)
               })?;
               */
        }

        Ok(())
    }

    fn on_file(&mut self, utx: &UtxHeader) -> Result<()> {
        let mut frt = self.get_frt(utx.channel) //todo::如何减少告警信息
            .ok_or(format!("文件通道{}没有配置,请检查配置文件", utx.channel))?;

        if frt.status != context::RUNNING {
            //dropped the packet if not running
            return Ok(());
        }

        if utx.head != 0 {
            if frt.file.is_some() {
                frt.reset_and_cleanup_unfinished_file(false); //has_tail_packet => false
            }

            let fh = Box::leak(unsafe{Box::from_raw(utx.payload as *mut FileHeader)});
            let rel_file = fh.file_name();
            let abs_file = format!("{}/{}.uploading", frt.fcc.local_root_path, rel_file); 
            let f = util::ensure_file(&abs_file, Some(50)).chain_err(||format!("文件通道{}无法创建本地文件{}", utx.channel, abs_file))?;
            frt.file_name = Some(rel_file);
            frt.file = Some(f);
            frt.utx_seq = utx.seq as i32;
            frt.hasher = Some(Xxh3::new());  // 初始化 XXH3 哈希计算器
            frt.file_hash = None;

            info!("文件通道{}接收到新文件{},seq={}", utx.channel, frt.file_name.as_ref().unwrap(), utx.seq);
        }
        else {
            frt.file.as_ref().ok_or(ErrorKind::Msg(format!("文件通道{},丢弃无主(无文件头)数据", utx.channel)))?;
            let diff = seqdiff(utx.seq as i32, frt.utx_seq);
            if diff != 1 && frt.utx_seq != -1 {
                frt.utx_lost += (diff-1) as u32;
                /*
                error!("文件通道{}发现丢包,数量={},文件={},seq jump from {} to {}", 
                    utx.channel, diff-1, frt.file_name.as_ref().unwrap_or(&"unnamed".to_string()),
                    frt.utx_seq, utx.seq);
                */
            }
            frt.utx_seq = utx.seq as i32;
        }

        let offset = if utx.head != 0 { std::mem::size_of::<FileHeader>() } else { 0 };
        let slice = unsafe {std::slice::from_raw_parts(utx.payload, utx.payload_size)};
//println!("seq={},content={}", utx.seq, String::from_utf8_lossy(&slice));

        // 更新哈希值（如果 hasher 已初始化）
        if let Some(ref mut hasher) = frt.hasher {
            hasher.update(&slice[offset..]);
        }

        if utx.tail == 0 {
            frt.append_file_cache(&slice[offset..])?;
        }
        else if frt.cache_len != 0 {
            frt.append_file_cache(&slice[offset..])?;
            frt.flush_file_cache()?;
        } else {
            frt.file.as_ref().unwrap().write(&slice[offset..])
                .chain_err(||format!("通道{}写文件失败", utx.channel))?;
            frt.file_size += (slice.len() - offset) as u64;
        }

        if utx.tail != 0 {
            // 计算最终哈希值
            let file_hash = frt.hasher.take()
                .map(|h| format!("{:016x}", h.digest()))
                .unwrap_or_default();
            frt.file_hash = Some(file_hash.clone());

            info!("文件通道{}接收文件'{}'完毕,丢包={},xxh3摘要(哈希值)={}", 
                utx.channel, 
                match frt.file_name.as_ref() { 
                    Some(s) => s.as_str(), 
                    None => "",
                },
                frt.utx_lost,
                file_hash,
            );

            if frt.utx_lost != 0 {
                frt.reset_and_cleanup_unfinished_file(true); //has_tail_packet => true
            } else {
                frt.reset_and_finishe_normally();
            }
        }

        Ok(())
    }

    /*
    fn on_file_ringbuf(&mut self, utx: &UtxHeader) -> Result<()> {
        let mut frt = self.get_frt(utx.channel) //todo::如何减少告警信息
            .ok_or(format!("文件通道{}没有配置,请检查配置文件", utx.channel))?;

        if frt.status != context::RUNNING {
            //dropped the packet if not running
            return Ok(());
        }

        if utx.head != 0 {
            if frt.file.is_some() {
                frt.reset_and_cleanup_unfinished_file(false); //has_tail_packet => false
            }

            let fh = Box::leak(unsafe{Box::from_raw(utx.payload as *mut FileHeader)});
            let rel_file = fh.file_name();
            let abs_file = format!("{}/{}.uploading", frt.fcc.local_root_path, rel_file); 
            let f = util::ensure_file(&abs_file).chain_err(||format!("文件通道{}无法创建本地文件{}", utx.channel, abs_file))?;
            frt.file_name = Some(rel_file);
            frt.file = Some(f);
            frt.utx_seq = utx.seq as i32;

            info!("文件通道{}接收到新文件{},seq={}", utx.channel, frt.file_name.as_ref().unwrap(), utx.seq);
        }
        else {
            frt.file.as_ref().ok_or(ErrorKind::Msg(format!("文件通道{},丢弃无主(无文件头)数据", utx.channel)))?;
            let diff = seqdiff(utx.seq as i32, frt.utx_seq);
            if diff != 1 && frt.utx_seq != -1 {
                frt.utx_lost += (diff-1) as u32;
                /*
                error!("文件通道{}发现丢包,数量={},文件={},seq jump from {} to {}", 
                    utx.channel, diff-1, frt.file_name.as_ref().unwrap_or(&"unnamed".to_string()),
                    frt.utx_seq, utx.seq);
                */
            }
            frt.utx_seq = utx.seq as i32;
        }

        let offset = if utx.head != 0 { std::mem::size_of::<FileHeader>() } else { 0 };
        let slice = unsafe {std::slice::from_raw_parts(utx.payload, utx.payload_size)};
//println!("seq={},content={}", utx.seq, String::from_utf8_lossy(&slice));

        if utx.tail == 0 {
            frt.append_file_cache(&slice[offset..])?;
        }
        else if frt.cache_len != 0 {
            frt.append_file_cache(&slice[offset..])?;
            frt.flush_file_cache()?;
        } else {
            frt.file.as_ref().unwrap().write(&slice[offset..])
                .chain_err(||format!("通道{}写文件失败", utx.channel))?;
            frt.file_size += (slice.len() - offset) as u64;
        }

        if utx.tail != 0 {
            info!("文件通道{}接收文件'{}'完毕,丢包={}", 
                utx.channel, 
                match frt.file_name.as_ref() { 
                    Some(s) => s.as_str(), 
                    None => "",
                },
                frt.utx_lost, 
            );

            if frt.utx_lost != 0 {
                frt.reset_and_cleanup_unfinished_file(true); //has_tail_packet => true
            } else {
                frt.reset_and_finishe_normally();
            }
        }

        Ok(())
    }
    */

    fn on_bloc(&mut self, utx: &UtxHeader) -> Result<()> {
        let mut frt = self.get_frt(utx.channel)
            .ok_or(format!("文件通道{}没有配置,请检查配置文件", utx.channel))?;

        if frt.status != context::RUNNING || frt.bloc_mode == BLOC_MODE_NONE {
            return Ok(()); //silentyly dropped the packet
        }

        if utx.head != 0 {
            let fh = Box::leak(unsafe{Box::from_raw(utx.payload as *mut FileHeader)});
            let rel_file = fh.file_name();
            let abs_file = format!("{}/{}", frt.fcc.local_root_path, rel_file);
            info!("文件通道{}接收新BLOC文件'{}'", utx.channel, rel_file);

            //drop last bloc session  and create a new bloc session
            frt.bloc = None;
            frt.bloc = Some(BlocRuntime::new(&abs_file, frt.bloc_mode, &frt.fcc)?);
        } else {
            let diff = seqdiff(utx.seq as i32, frt.utx_seq);
            if diff != 1 && frt.utx_seq != -1 {
                frt.utx_lost += (diff-1) as u32;
                warn!("文件(BLOC)通道{}发现丢包,数量={}", utx.channel, diff-1);
            }
        }

        frt.utx_seq = utx.seq as i32;

        //if the head_packet was lost, bloc filename cannot be correctly identified,  
        //the data will be written to the "lost-xxxx" bloc file.
        if frt.bloc.is_none() {
            let abs_file = format!("{}/lost", frt.fcc.local_root_path);
            frt.bloc = Some(BlocRuntime::new(&abs_file, frt.bloc_mode, &frt.fcc)?);
        }

        if let Some(bloc) = &mut frt.bloc {
            match frt.bloc_mode {
                BLOC_MODE_FTP => bloc.process_bloc_with_ftp(utx, &frt.fcc)?,
                BLOC_MODE_UDP => bloc.process_bloc_with_udp(utx)?,
                _ => {},
            }
        }
 
        Ok(())
    }

    fn on_sys(&mut self, utx: &UtxHeader) -> Result<()> {
        let req = unsafe {
            let slice = std::slice::from_raw_parts(utx.payload, utx.payload_size);
            std::str::from_utf8(slice).unwrap() //todo
        };

        match req {
            "timer" => self.on_timer(utx),
            _ => self.on_ctrl(utx, req),
        }
    }

    fn on_timer(&mut self, _utx: &UtxHeader) -> Result<()> {
        for drt in &mut self.drts {
            debug!("datagram channel {}: traffic_in={}, traffic_out={}, packets={}", 
                drt.channel, drt.traffic_in, drt.traffic_out, drt.traffic_packets);
            if drt.audit && (drt.traffic_in != 0 || drt.traffic_out != 0) {
                let time = time::get_time();
                let dar =  audit::DatagramAuditRecord {
                    time_sec: time.sec,
                    time_nsec: time.nsec,
                    channel: drt.channel as u8,
                    vchannel: drt.vchannel,
                    side: audit::AS_RX,
                    event: audit::AE_DATAGRAM_STATS,
                    result: audit::AR_OK,
                    result_msg: "".to_string(),
                    ip: format!("{}", drt.peer_addr.ip()),
                    traffic_in: drt.traffic_in as i64,
                    traffic_out: drt.traffic_out as i64,
                    interval: config::FLOW_STATISTICS_INTERVAL,
                };
                audit::audit_d(&dar);
            }
            drt.traffic_in = 0;
            drt.traffic_out = 0;
            drt.traffic_packets = 0;
        }

        Ok(())
    }

    fn on_ctrl(&mut self, _utx: &UtxHeader, req: &str) -> Result<()> {
        info!("on_ctrl() receive '{}'", req);
        let (action, channel) = decode(req);
        match action.to_lowercase().as_str() {
            "reload" => {
                self.reload_config();
            }
            "start_file_channel" => {
                if let Some(fcc) = self.config.get_fcc(channel as usize) {
                    let frt = FileRuntime::new(fcc.clone())?;
                    self.set_frt(channel as u8, frt);
                    self.ctrl_report("OK","channel has been started");
                } else {
                    self.ctrl_report("FAIL","channel is not configured");
                }
            }
            "stop_file_channel" => {
                if let Some(frt) = self.get_frt(channel as u8) {
                    frt.status = context::STOPPED;
                    self.ctrl_report("OK","channel has been stopped");
                } else {
                    self.ctrl_report("FAIL","channel is not configured");
                }
            }
            "list_file_channel" => {
                let mut info = String::with_capacity(256*10);
                for frt in &self.frts {
                    info += format!("({},{}),", frt.fcc.channel, context::STATUS_NAMES[frt.status]).as_str();
                }
                self.ctrl_report("OK",&info);
            }
            "start_datagram_channel" => {
                if let Some(dcc) = self.config.get_dcc(channel as usize) {
                    let drt = DatagramRuntime::new_from_dcc(dcc.clone())?;
                    self.set_drt(channel as u8, drt);
                    self.ctrl_report("OK","channel has been started");
                } else {
                    self.ctrl_report("FAIL","channel is not configured");
                }
            }
            "stop_datagram_channel" => {
                if let Some(drt) = self.get_drt(channel as u8) {
                    drt.status = context::STOPPED;
                    self.ctrl_report("OK","channel has been stopped");
                } else {
                    self.ctrl_report("FAIL","channel is not configured");
                }
            }
            "list_datagram_channel" => {
                let mut info = String::with_capacity(256*10);
                for drt in &self.drts {
                    info += format!("({},{}),", drt.channel, context::STATUS_NAMES[drt.status]).as_str();
                }
                self.ctrl_report("OK",&info);
            }
            _ => {
                error!("unsupported operation:{}", action);
                self.ctrl_report("FAIL","invalid command");
            }
        }
        Ok(())
    }
}

extern "C" 
fn utx_handler(
    _urt: *mut c_void,
    utx_type: u8,
    channel: u8,
    seq: u16,
    head: u8,
    tail: u8,
    check: u16,
    _session_id: u16,
    packet_opt: u8,
    packet_head: u8,
    packet_tail: u8,
    payload: *mut u8,
    payload_size: u16,
) {
    let urt = Box::leak(unsafe {Box::from_raw(_urt as *mut UtxRuntime)});
    let uh = UtxHeader {
        _utx_type: utx_type,
        channel: channel,
        seq: seq,
        head: head,
        tail: tail,
        _check: check,
        packet_opt: packet_opt,
        packet_head: packet_head,
        packet_tail: packet_tail,
        payload: payload,
        payload_size: payload_size as usize,
    };

    match utx_type {
        utx::UTX_TYPE_DATAGRAM | utx::UTX_TYPE_AGENT => {
            if let Err(e) = urt.on_datagram(&uh) {
                util::log_error(&e);
            }
        }
        utx::UTX_TYPE_FILE => {
            if let Err(e) = urt.on_file(&uh) {
                util::log_error(&e);
            }
        }
        /*
        utx::UTX_TYPE_AGENT => {
            if let Err(e) = urt.on_datagram(&uh) { //agent的utx通信方式与datagram完全一样(除了UTX_TYPE取值不一样)
                util::log_error(&e);
            }
        }
        */
        utx::UTX_TYPE_BLOCK => {
            if let Err(e) = urt.on_bloc(&uh) {
                util::log_error(&e);
            }
        }
        utx::UTX_TYPE_SYS => {
            if let Err(e) = urt.on_sys(&uh) {
                util::log_error(&e);
            }
       }
        _ => {
            trace!("error: utx_type {} not supported", utx_type);
        }
    }
}

fn timer_run (v_fd: Vec<i32>) {
    let builder = thread::Builder::new();
    let _ = builder
        .name("timer-thread".to_string())
        .spawn(move||{
            timer_thread_handler(v_fd);
        }).unwrap();
}

fn timer_thread_handler(v_fd: Vec<i32>) {
    loop {
        thread::sleep(Duration::from_secs(config::FLOW_STATISTICS_INTERVAL.into()));
        for fd in &v_fd {
            util::c_write(*fd, b"timer"); //触发主进程on_sys()
        }
        debug!("timer_thread trigger...");
    }
}

fn ctrl_run(
    utx_root: &str,
    v_fd: Vec<i32>,
    v_rx: Vec<Receiver<(String,String)>>,
) {
    if let Err(e) = ctrl_thread_handler(utx_root, v_fd, v_rx) {
        util::log_error(&e);
        std::process::exit(-1);
    }
}

fn ctrl_thread_handler(
    utx_root: &str,
    v_fd: Vec<i32>,
    v_rx: Vec<Receiver<(String,String)>>,
) -> Result<()> {
    let listener = util::init_unix_listener(utx_root, PROG_NAME)?;
    info!("ctrl unix_listener created");

    loop {
        info!("ctrl ready to accept...");
        let (stream, _src) = match listener.accept() {
            Ok((stream, _src)) => (stream, _src),
            Err(e) => {
                error!("ctrl accept error:{:?}", e);
                continue;
            }
        };

        trace!("ctrl accept a stream:{:?}", stream);
        loop {
            let mut msg: ThreadMsg = match bincode::deserialize_from(&stream) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("ctrl 读取请求失败:{:?}",e);
                    break;
                }
            };
            trace!("ctrl receive a msg {:?}", msg);

            let action = match msg.action {
                ThreadAction::CtrlInit => continue,
                ThreadAction::CtrlListFileChannel => "list_file_channel",
                ThreadAction::CtrlStartFileChannel => "start_file_channel",
                ThreadAction::CtrlStopFileChannel => "stop_file_channel",
                ThreadAction::CtrlListDatagramChannel => "list_datagram_channel",
                ThreadAction::CtrlStartDatagramChannel => "start_datagram_channel",
                ThreadAction::CtrlStopDatagramChannel => "stop_datagram_channel",
                _ => "unknown",
            };

            let req = format!("{} {}", action, msg.channel);

            for i in 0..v_fd.len() {
                util::c_write(v_fd[i], req.as_bytes());     //触发主进程on_sys()
                let (code,info) = v_rx[i].recv().unwrap();  //等待主进程处理结果
                msg.action = if code == "OK" { ThreadAction::CtrlOk } else { ThreadAction::CtrlFail };
                msg.object = info;
                match bincode::serialize_into(&stream, &msg) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("ctrl 发送序列化对象失败:{:?}",e);
                    }
                }
            }
        }
    }
    //Ok(())
}

fn run_a_physical_interface(
    pp: &'static util::ProgParam, 
    config: TxConfig, 
    pi: config::PhysicalInterface,
    notify_read_fd: i32,            //for receive notify from ctrl_thread and timer_thread
    tx: Sender<(String, String)>,   //for send reponse to ctrl_thread
) -> Result<()> {
    let mut urt = Box::new(UtxRuntime {
        pp: pp,
        config: config,
        drts: Vec::new(),
        adrts: Vec::new(),
        frts: Vec::new(),
        channel_to_drt_index: [INVALID_INDEX; 256],
        channel_to_adrt_index: [INVALID_INDEX; 256],
        channel_to_frt_index: [INVALID_INDEX; 256],
        tx: tx,
    });

    for dcc in &urt.config.dccs {
        let drt = DatagramRuntime::new_from_dcc(dcc.clone())?;
        urt.channel_to_drt_index[dcc.channel] = urt.drts.len();
        urt.drts.push(drt);
    }

    for fcc in &urt.config.fccs {
        match fcc.mode {
            ChannelMode::ClientPushAgent(_) => {
                let adrt = DatagramRuntime::new_from_fcc(fcc.clone())?;
                urt.channel_to_adrt_index[fcc.channel] = urt.adrts.len(); //TODO!!! file channel conflict with datagram channel!
                urt.adrts.push(adrt);
            }
            _ => {
                let frt = FileRuntime::new(fcc.clone())?;
                urt.channel_to_frt_index[fcc.channel] = urt.frts.len();
                urt.frts.push(frt);
            }
        }
    }

    let urx = UtxReceiver::new(
        &pi.rx_mac, 
        Some(utx_handler),
    ) 
    .ok_or(ErrorKind::UnrecoverableError(line!(),
        format!("创建Utx失败,请检查配置.pi_index={},interface={},rx_mac={}", pi.pi_index, pi.if_name, pi.rx_mac)))?;

    info!("pi-thread(pi_index={}) created and initialized ok, ready to work...", pi.pi_index);
    urx.run(notify_read_fd, Box::into_raw(urt) as *mut c_void);
    Ok(())
}

fn run(pp: &'static util::ProgParam, config: TxConfig) -> Result<()> {

    if config.gc.side != config::SIDE_RX {
        None.ok_or(ErrorKind::UnrecoverableError(line!(),
            "es序只能运行在rx端,请检查配置文件的side配置选项".to_string()))?;
    }

    util::init_log(&pp.utx_root, PROG_NAME, &config.gc.log_level)?;
    if pp.daemonize {
        util::daemonize(&pp.utx_root, PROG_NAME)?;
    }

    util::init_audit(pp, &config.gc.audit_db_conn_string, config.file_audit_needed || config.datagram_audit_needed);

    let mut v_rx: Vec<Receiver<(String, String)>> = Vec::new();
    let mut v_notify_write_fd: Vec<i32> = Vec::new();

    for pi in &config.gc.physical_interfaces {
        let (tx,rx) = mpsc::channel();
        let (notify_read_fd, notify_write_fd) = util::c_pipe()?;
        let thread_pi = pi.clone();
        let thread_config = config.clone();

        v_rx.push(rx);
        v_notify_write_fd.push(notify_write_fd);

        let builder = thread::Builder::new();
        let _handle = builder
            .name(format!("pi-{}", thread_pi.pi_index))
            .spawn(move||{
                if let Err(e) = run_a_physical_interface(pp, thread_config, thread_pi.clone(), notify_read_fd, tx) {
                    util::log_error(&e);
                    error!("pi-thread(pi_index={}) encounter unrecoverable error:{:?}", thread_pi.pi_index, e);
                    error!("pi-thread(pi_index={}) exitting...", thread_pi.pi_index);
                }
            }).unwrap();
    }

    timer_run(v_notify_write_fd.clone());
    ctrl_run(&pp.utx_root, v_notify_write_fd, v_rx);

    Ok(())
}

fn main() {
    lazy_static! {
        static ref PP: util::ProgParam = util::parse_args();
    }
    let config = util::load_config(&PP, true, true, false);
    utx::UtxReceiver::set_rx_mtu(config.gc.mtu);
    utx::UtxReceiver::set_rx_buffer_size_mb(config.gc.rx_buffer_size_mb);

    if let Err(e) = run(&PP, config) {
        util::log_error(&e);
        std::process::exit(-1);
    }
}

