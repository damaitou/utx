
use std::io::{Write,Read};
use std::fs::File;
use std::os::raw::{c_void, c_char, c_int};
use std::os::unix::io::AsRawFd;
use std::ffi::CStr;
use log::{error, warn, info, debug, trace};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use std::net::{SocketAddr, IpAddr};
use mio::net::{UdpSocket, TcpStream, TcpListener};
use mio::unix::EventedFd;
use mio::*;

#[link(name = "utx", kind = "static")]
extern "C" {
    fn bind_socket_to_interface(
        s: c_int,
        if_name: *const u8, 
    ) -> c_int;
}

#[macro_use]
extern crate lazy_static;

use mylib::config::{self, TxConfig, INVALID_INDEX};
use mylib::utx::{self, UtxSender, UtxReceiver};
use mylib::errors::*;
use mylib::audit;
use mylib::util;
use mylib::context::{self, ThreadMsg};

const PROG_NAME: &'static str = "btx";

struct UtxHeader {
    _utx_type: u8,
    channel: u8,
    seq: u16,
    head: u8,
    tail: u8,
    _check: u16,
    session_id: u16,
    _packet_opt: u8,
    _packet_head: u8,
    _packet_tail: u8,
    payload: *mut u8,
    payload_size: usize,
}

struct UtxTcp {
    initiator: bool, //true=发起者;false=参与者
    channel: usize,
    stream: TcpStream,
    connected: bool,
    traffic: usize,
    this_seq: u16,          //sequence of this_side to utx_peer transmission
    peer_seq: u16,          //sequence of utx_peer to this_side transmission
    utx_lost: u32,          //how many utxs lost during utx_peer to this_side transmission
    utx_session_id: u16,    //session_id of this_side<->utx_peer conversation
}

impl UtxTcp {
    fn connect(&mut self, us: &UtxSender) {
        us.tcp_connect(self.channel, self.utx_session_id, &mut self.this_seq);
    }
    fn connect_resp(&mut self, us: &UtxSender, success: bool) {
        us.tcp_connect_resp(self.channel, self.utx_session_id, &mut self.this_seq, success);
    }
    fn disconnect(&mut self, us: &UtxSender) {
        us.tcp_disconnect(self.channel, self.utx_session_id, &mut self.this_seq,
            if self.initiator { utx::BTX_TYPE_TCP_T2R } else { utx::BTX_TYPE_TCP_R2T } );
    }
    fn send_data(&mut self, us: &UtxSender, buf: &[u8]) {
        us.tcp_send_data(
            self.channel, 
            self.utx_session_id, 
            &mut self.this_seq,
            if self.initiator { utx::BTX_TYPE_TCP_T2R } else { utx::BTX_TYPE_TCP_R2T },
            buf
        );
    }
}

/*
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
*/

#[repr(C)]
struct UtxRuntime {
    pp: &'static util::ProgParam,
    config: TxConfig,
    poll: Poll,
    listeners: HashMap<usize, TcpListener>,
    tcps: HashMap<usize, UtxTcp>,
    tcp_session_seqs: [u16; 256],
    utx_sender: UtxSender,
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

    fn alloc_session_id(&mut self, channel:u8) -> u16 {
        let ret = self.tcp_session_seqs[channel as usize];
        self.tcp_session_seqs[channel as usize] += 2;
        ret
    }

    fn calc_token(channel:u8, session_id: u16) -> u32 {
        ((channel as u32 +1) <<16) | (session_id as u32)
    }

    fn on_utx_packet(&mut self, urx: &UtxReceiver) {
        /*
         * looping on utx ring_buffer to process available utx packets.
         * if there's packet to process, utx_handler() will be triggered
         */
        urx.loop_on_available_packets(self as *mut _ as *mut c_void);
    }

    fn on_listener(&mut self, channel:usize) {
        let listener = self.listeners.get_mut(&channel);
        match listener {
            Some(listener) => {
                match listener.accept() {
                    Ok((stream, _cliaddr)) => {
                        let mut tcp = UtxTcp {
                            initiator: true,
                            channel: channel,
                            stream: stream,
                            connected: false,
                            traffic: 0,
                            this_seq: 0,
                            peer_seq: 0,
                            utx_lost: 0,
                            utx_session_id: self.alloc_session_id(channel as u8),
                        };
                        let token_id = UtxRuntime::calc_token(channel as u8, tcp.utx_session_id) as usize;
                        match self.poll.register(&tcp.stream, Token(token_id), Ready::readable(), PollOpt::level()) {
                            Ok(_) => {
                                tcp.connect(&self.utx_sender);
                                self.tcps.insert(token_id, tcp);
                                trace!("TcpStream of token({}) registered to poll ok.", token_id);
                            }
                            Err(e) => {
                                error!("channel({}) registering tx-side TcpStream of token({}) error:{:?}", channel, token_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("channel({}) accepting connection error:{:?}", channel, e);
                    }
                }
            }
            None => {
                error!("listener of channel({}) not found in hashmap!", channel);
            }
        }
    }

    fn on_tcp_data(&mut self, token: usize) {
        trace!("on_tcp_data(), token={}", token);
        let tcp = self.tcps.get_mut(&token);
        match tcp {
            Some(tcp) => {
                let mut buf = [0 as u8;4096]; //TODO!! tunning the buffer size
                let mut tcp_disconnected = false;
                match tcp.stream.read(&mut buf) {
                    Ok(size) => {
                        if size == 0 {
                            tcp_disconnected = true;
                        } else {
                            tcp.send_data(&self.utx_sender, &buf[..size]);
                            tcp.traffic += size;
                        }
                    }
                    Err(e) => {
                        error!("error reading data from TcpStreamof token({}):{:?}", token, e);
                        tcp_disconnected = true;
                    }
                }
                if tcp_disconnected == true {
                    warn!("TcpStream of token({}) disconnected, removing...", token);
                    tcp.disconnect(&self.utx_sender);
                    self.tcps.remove(&token);
                }
            }
            None => {
                error!("TcpStream of token({}) not found in hashmap!", token);
            }
        }
    }

    fn on_utx_tcp_t2r(&mut self, uh: &UtxHeader) -> Result<()> {
        trace!("on_utx_tcp_t2r(),seq={},head={},tail={},session={},payload_size={}", 
            uh.seq, uh.head, uh.tail, uh.session_id, uh.payload_size);
        if uh.head != 0 {
            self.on_utx_tcp_connect(uh)
        } else if uh.tail != 0 {
            self.on_utx_tcp_disconnect(uh)
        } else {
            self.on_utx_tcp_data(uh)
        }
    }

    fn on_utx_tcp_r2t(&mut self, uh: &UtxHeader) -> Result<()> {
        trace!("on_utx_tcp_t2r(),seq={},head={},tail={},session={},payload_size={}", 
            uh.seq, uh.head, uh.tail, uh.session_id, uh.payload_size);
        if uh.head != 0 {
            self.on_utx_tcp_connect_resp(uh)
        } else if uh.tail != 0 {
            self.on_utx_tcp_disconnect(uh)
        } else {
            self.on_utx_tcp_data(uh)
        }
    }

    fn on_utx_tcp_connect(&mut self, uh: &UtxHeader) -> Result<()> {
        let channel = uh.channel as usize;
        match self.config.get_tcc(channel as usize) {
            Some(tcc) => {
                let ip:IpAddr = tcc.host.parse().unwrap(); //todo
                let addr = SocketAddr::new(ip, tcc.port);
                match TcpStream::connect(&addr) { //TODO!!this would block the whole thread!!!
                    Ok(stream) => {
                        let mut tcp = UtxTcp {
                            initiator: false,
                            channel: channel,
                            stream: stream,
                            connected: true,
                            traffic: 0,
                            this_seq: 0,
                            peer_seq: uh.seq,
                            utx_lost: 0,
                            utx_session_id: uh.session_id,
                        };
                        let token_id = UtxRuntime::calc_token(channel as u8, uh.session_id) as usize;
                        match self.poll.register(&tcp.stream, Token(token_id), Ready::readable(), PollOpt::level()) {
                            Ok(_) => {
                                tcp.connect_resp(&self.utx_sender, true);
                                self.tcps.insert(token_id, tcp);
                                trace!("TcpStream of token({}) registered to poll ok.", token_id);
                            }
                            Err(e) => {
                                error!("channel({}) registering rx-side TcpStream of token({}) error:{:?}", channel, token_id, e);
                            }
                        }
                    }
                    Err(e) => {
                        let mut tmp_seq:u16 = 0;
                        self.utx_sender.tcp_connect_resp(channel, 0, &mut tmp_seq, false);
                        warn!("channel({}) connecting {}:{} error:{:?}", channel, tcc.host, tcc.port, e);
                    }
                }
            }
            None => {
                let mut tmp_seq:u16 = 0;
                self.utx_sender.tcp_connect_resp(channel, 0, &mut tmp_seq, false); //tcp connection of rx side failed
            }
        }
        Ok(())
    }

    fn on_utx_tcp_disconnect(&mut self, uh: &UtxHeader) -> Result<()> {
        let token_id = UtxRuntime::calc_token(uh.channel as u8, uh.session_id) as usize;
        let tcp = self.tcps.remove(&token_id);
        match tcp {
            Some(_tcp) => {
                debug!("on_tcp_disconnect_t2r(), TcpStream of token({}) disconnected", token_id);
            }
            None => {
                error!("on_tcp_disconnect_t2r(), TcpStream of token({}) not found in hashmap!", token_id);
            }
        }
        Ok(())
    }

    fn on_utx_tcp_data(&mut self, uh: &UtxHeader) -> Result<()> {
        let token_id = UtxRuntime::calc_token(uh.channel as u8, uh.session_id) as usize;
        let tcp = self.tcps.get_mut(&token_id);
        match tcp {
            Some(tcp) => {
                let diff = seqdiff(uh.seq as i32, tcp.peer_seq as i32);
                if diff != 1 {
                    tcp.utx_lost += (diff-1) as u32;
                    warn!("channel({}) session({}) LOST {} packets:seq jump from {} to {}", 
                        uh.channel, uh.session_id, diff-1, tcp.peer_seq, uh.seq);
                }
                tcp.peer_seq = uh.seq;
                let payload = unsafe {std::slice::from_raw_parts(uh.payload, uh.payload_size)};
                match tcp.stream.write(&payload) {
                    Ok(_) => {
                        tcp.traffic += uh.payload_size;
                    },
                    Err(e) => {
                        tcp.disconnect(&self.utx_sender);
                        self.tcps.remove(&token_id);
                        warn!("channel({}) writing TcpStream of token({}) error:{:?}", uh.channel, token_id, e);
                    }
                }
            }
            None => {
                error!("on_tcp_data_t2r(), TcpStream of token({}) not found in hashmap!", token_id);
                //TODO:should send disconnect utx packet to peer?
            }
        }
        Ok(())
    }


    fn on_utx_tcp_connect_resp(&mut self, uh: &UtxHeader) -> Result<()> {
        let token_id = UtxRuntime::calc_token(uh.channel as u8, uh.session_id) as usize;
        let tcp = self.tcps.get_mut(&token_id);
        match tcp {
            Some(tcp) => {
                if uh.head != 0 {
                    debug!("on_tcp_connect_r2t(), tcp_connection of utx_pee(token={}) established successfully", token_id);
                    tcp.connected = true;
                    tcp.peer_seq = uh.seq;
                }
                else {
                    warn!("on_tcp_connect_r2t(), tcp_connection of utx_peer(token={}) rejected.", token_id);
                    self.tcps.remove(&token_id);
                }
            }
            None => {
                error!("on_tcp_data_r2t(), TcpStream of token({}) not found in hashmap!", token_id);
                //TODO:should send disconnect utx packet to peer?
            }
        }
        Ok(())
    }

    fn ctrl_report(&self, code: &str, info: &str) {
        if let Err(e) = self.tx.send((code.to_string(), info.to_string())) {
            error!("Sender::send() error, code={},info={},error={:?}", code, info, e);
            std::process::exit(-1);
        }
    }

    fn reload_config(&mut self) {
        eprintln!("reloading config..."); 
        self.config = util::load_config(&self.pp, false, false, true);
    }

    /*
    fn on_sys(&mut self, utx: &UtxHeader) -> Result<()> {
        let req = unsafe {
            let slice = std::slice::from_raw_parts(utx.payload, utx.payload_size);
            std::str::from_utf8(slice).unwrap() //todo
        };
        trace!("on_sys(), payload='{}'", req);

        match req {
            "timer" => self.on_timer(utx),
            _ => Ok(()),
               //self.on_ctrl(utx, req),
        }
    }
    */

    /*
    fn on_timer(&mut self, _utx: &UtxHeader) -> Result<()> {
        for drt in &mut self.drts {
            if drt.dcc.audit && (drt.traffic_in != 0 || drt.traffic_out != 0) {
                let time = time::get_time();
                let dar =  audit::DatagramAuditRecord {
                    time_sec: time.sec,
                    time_nsec: time.nsec,
                    channel: drt.dcc.channel as u8,
                    vchannel: drt.dcc.vchannel,
                    side: audit::AS_RX,
                    event: audit::AE_DATAGRAM_STATS,
                    result: audit::AR_OK,
                    result_msg: "".to_string(),
                    ip: drt.dcc.host.clone(),
                    traffic_in: drt.traffic_in as i64,
                    traffic_out: drt.traffic_out as i64,
                    interval: config::FLOW_STATISTICS_INTERVAL,
                };
                audit::audit_d(&dar);
                
                drt.traffic_in = 0;
                drt.traffic_out = 0;
            }
        }

        Ok(())
    }
    */

    /*
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
                    let drt = DatagramRuntime::new(dcc.clone())?;
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
                    info += format!("({},{}),", drt.dcc.channel, context::STATUS_NAMES[drt.status]).as_str();
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
    */
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
    session_id: u16,
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
        session_id: session_id,
        _packet_opt: packet_opt,
        _packet_head: packet_head,
        _packet_tail: packet_tail,
        payload: payload,
        payload_size: payload_size as usize,
    };

    match utx_type {
        utx::UTX_TYPE_DATAGRAM => {
            return;
            /*
            if let Err(e) = urt.on_datagram(&uh) {
                util::log_error(&e);
            }
            */
        }
        utx::UTX_TYPE_SYS => {
            return;
            /*
            if let Err(e) = urt.on_sys(&uh) {
                util::log_error(&e);
            }
            */
        }
        utx::BTX_TYPE_TCP_T2R => {
            if let Err(e) = urt.on_utx_tcp_t2r(&uh) {
                util::log_error(&e);
            }
        }
        utx::BTX_TYPE_TCP_R2T => {
            if let Err(e) = urt.on_utx_tcp_r2t(&uh) {
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
        //debug!("timer_thread trigger...");
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
            if msg.action == "CTRL_INIT" {
                continue;
            }

            let req = format!("{} {}", msg.action, msg.channel);

            for i in 0..v_fd.len() {
                util::c_write(v_fd[i], req.as_bytes()); //触发主进程on_sys()
                let (code,info) = v_rx[i].recv().unwrap(); //等待主进程处理结果
                msg.action = code;
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

//TOKEN usage
//0:                for UTX_SOCKET
//1-65535:          for tcp_listener, each token mapped to channel number
//66000 & above:    for active tcp connection
const TOKEN_UTX_SOCKET: Token = Token(0);
const TOKEN_TCP_CONNECTION_START: usize = 66000;

fn run_a_physical_interface(
    pp: &'static util::ProgParam, 
    config: TxConfig, 
    pi: config::PhysicalInterface,
    notify_read_fd: i32,            //for receive notify from ctrl_thread and timer_thread
    tx: Sender<(String, String)>,   //for send reponse to ctrl_thread
) -> Result<()> {

    /*
    let us = UtxSender::new(&pi.tx_mac, &pi.rx_mac)
        .ok_or(ErrorKind::UnrecoverableError(line!(),
            format!("创建UtxSender失败,请检查配置.pi_index={},interface={},tx_mac={}, rx_mac={}", pi.pi_index, pi.if_name, pi.tx_mac, pi.rx_mac))
        )?;
    */
    let us = match config.gc.side {
        config::SIDE_TX => UtxSender::new(&pi.tx_mac, &pi.rx_mac)
            .ok_or(ErrorKind::UnrecoverableError(line!(),
                format!("创建UtxSender失败,请检查配置.pi_index={},interface={},tx_mac={}, rx_mac={}", pi.pi_index, pi.if_name, pi.tx_mac, pi.rx_mac))
            )?,
        config::SIDE_RX => UtxSender::new(&pi.rx_mac, &pi.tx_mac)
            .ok_or(ErrorKind::UnrecoverableError(line!(),
                format!("创建UtxSender失败,请检查配置.pi_index={},interface={},tx_mac={}, rx_mac={}", pi.pi_index, pi.if_name, pi.tx_mac, pi.rx_mac))
            )?,
        _ => unreachable!(),
    };

    let urx = match config.gc.side {
        config::SIDE_TX => UtxReceiver::new(&pi.tx_mac, Some(utx_handler)) 
            .ok_or(ErrorKind::UnrecoverableError(line!(),
                format!("创建UtxReceiver失败,请检查配置.pi_index={},interface={},rx_mac={}", pi.pi_index, pi.if_name, pi.rx_mac))
            )?,
        config::SIDE_RX => UtxReceiver::new(&pi.rx_mac, Some(utx_handler)) 
            .ok_or(ErrorKind::UnrecoverableError(line!(),
                format!("创建UtxReceiver失败,请检查配置.pi_index={},interface={},rx_mac={}", pi.pi_index, pi.if_name, pi.rx_mac))
            )?,
        _ => unreachable!(),
    };

    let tcp_session_seq_start:u16 = match config.gc.side {
        config::SIDE_TX => 0,
        config::SIDE_RX => 1,
        _ => unreachable!(),
    };

    let mut urt = Box::new(UtxRuntime {
        pp: pp,
        config: config,
        poll: Poll::new().unwrap(),
        listeners: HashMap::new(),
        tcps: HashMap::new(),
        tcp_session_seqs: [tcp_session_seq_start; 256],
        utx_sender: us,
        tx: tx,
    });

    let utx_socket_fd =  urx.get_socket_fd();
    urt.poll.register(&EventedFd(&utx_socket_fd), TOKEN_UTX_SOCKET, Ready::readable(), PollOpt::level())
        .chain_err(||"在Poll实例中注册UtxSocketFd失败")?;

    for tcc in &urt.config.tccs {
        if let config::Role::Server = tcc.role {
            let ip:IpAddr = tcc.host.parse().unwrap(); //todo
            let addr = SocketAddr::new(ip, tcc.port);
            let listener = TcpListener::bind(&addr).unwrap(); //todo
            let token = Token(tcc.channel);
            urt.poll.register(&listener, token, Ready::readable(), PollOpt::level())
                .chain_err(||"在Poll实例中注册TcpListener失败")?;
            urt.listeners.insert(tcc.channel, listener);
        }
    }

    info!("pi-thread(pi_index={}) created and initialized ok, ready to work...", pi.pi_index);

    let mut events = Events::with_capacity(1024);
    loop {
        urt.poll.poll(&mut events, None).chain_err(||"poll()失败")?;
        for event in events.iter() {
            match event.token() {
                TOKEN_UTX_SOCKET => urt.on_utx_packet(&urx),
                Token(token) => {
                    if token<TOKEN_TCP_CONNECTION_START {
                        urt.on_listener(token);
                    } 
                    else {
                        urt.on_tcp_data(token);
                    }
                }
                /*
                TOKEN_TIMER => rt.on_timer(),
                TOKEN_CONTROL => {
                    if let Err(e) = rt.on_control() {
                        util::log_error(&e);
                        let raw_fd = &rt.ctrl_stream.as_ref().unwrap().as_raw_fd();
                        rt.poll.deregister(&EventedFd(raw_fd)).
                            chain_err(||{format!("在Poll中注册Client{:?}失败",&rt.ctrl_stream)})?;
                        rt.ctrl_stream = None;
                    }
                }
                Token(id) =>  rt.on_udp(id),
                */
            }
        }
    }

    //urx.run(notify_read_fd);
    //Ok(())
}

fn run(pp: &'static util::ProgParam, config: TxConfig) -> Result<()> {

    /*
    if config.gc.side != config::SIDE_RX {
        None.ok_or(ErrorKind::UnrecoverableError(line!(),
            "es序只能运行在rx端,请检查配置文件的side配置选项".to_string()))?;
    }
    */

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
    let config = util::load_config(&PP, false, false, true);
    utx::UtxSender::set_tx_mtu(config.gc.mtu);
    utx::UtxReceiver::set_rx_mtu(config.gc.mtu);
    utx::UtxReceiver::set_rx_buffer_size_mb(config.gc.rx_buffer_size_mb);

    if let Err(e) = run(&PP, config) {
        util::log_error(&e);
        std::process::exit(-1);
    }
}

