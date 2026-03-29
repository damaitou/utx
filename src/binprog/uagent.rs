
/* uagent: 光闸程序
 *
 *                          |--(utx)-->LINK--(utx)--->
 *                          |                         |
 *   CLIENT <-(tx_tcp)--> UPROXY                   UPROXY<-(rx_tcp)-->SERVER
 *                          |                         |
 *                          |<--(utx)--LINK<-(utx)<---|
 *
 */

use std::env;
use std::path::PathBuf;
use std::io::{self, Read, Write};
use std::net::{SocketAddr};
use std::os::unix::io::{RawFd, AsRawFd};
use log::{error, warn, info, debug, trace};
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::unix::EventedFd;
use mio::*;
use mylib::errors::*;
use async_std::task;

mod util;
use util::mychannel::{self,*};
use util::poller::*;

const TCP_CONNECT:u16       = 1<<0; //Tx to Rx signal, request to establish TcpSession, should not carry data
const TCP_DISCONNECT:u16    = 1<<1; //signal to peer that TcpSession has been terminated, should not carry data
#[repr(C)]
struct UPacket {
    tcp_id: u16,
    flags: u16,
    data_len: u32,
    data:[u8; 64*1024-8],
}
impl UPacket {
    fn new() -> UPacket {
        UPacket {
            tcp_id: 0,
            flags: 0,
            data_len: 0,
            data: [0 as u8; 64*1024-8],
        }
    }
}

enum PollObject {
    MyReceiver(MyReceiver),
    TcpListener(TcpListener),
    TxTcpSession(TxTcpSession),
    RxTcpSession(RxTcpSession),
    UtxSender(UtxSender),
    //UdpServer(UdpSocket),
}

impl PollableObject for PollObject {
    fn register_me (&self, obj_id:usize, poll:&mio::Poll) -> io::Result<()> {
        let fd: RawFd;
        let ef: EventedFd;
        let evented: &dyn Evented = match self {
            PollObject::TcpListener(l) => l,
            PollObject::UdpServer(u) => u,
            PollObject::TxTcpSession(t) => &t.stream,
            PollObject::RxTcpSession(t) => {
                match t.stream.as_ref() {
                    Some(stream) => stream,
                    None => {
                        return Err(io::Error::new(std::io::ErrorKind::Other, 
                            format!("register_object(),rx_tcp#{}尚未建立连接",obj_id)));
                    }
                }
            },
            PollObject::MyReceiver(r) => {
                fd = r.as_raw_fd();
                ef = EventedFd(&fd); 
                &ef 
            }
        };

        poll.register(evented, Token(obj_id), Ready::readable(), PollOpt::level())
    }
}

impl Drop for PollObject {
    fn drop(&mut self) {
        trace!("PollObject being dropped");
    }
}

struct TxTcpSession {
    tcp_id: usize,
    stream: TcpStream,
}
impl TxTcpSession {
}

struct RxTcpSession {
    tcp_id: usize,
    stream: Option<TcpStream>,
    cache: Option<([u8;64*1024], usize)>,
}
impl RxTcpSession {
    fn cache_data(&mut self, data: &[u8]) -> usize {
        if self.cache.is_none() {
            self.cache = Some(([0;64*1024],0));
        }
        let (cache,used_len) = self.cache.as_mut().unwrap();
        let available = cache.len() - *used_len;
        let copy_len = std::cmp::min(data.len(), available);
        trace!("used_len={},available={},data.len()={},copy_len={}",*used_len,available,data.len(),copy_len);
        if copy_len > 0 {
            cache[*used_len..*used_len+copy_len].copy_from_slice(&data[..copy_len]);
            *used_len += copy_len
        }
        copy_len
    }
    fn process_data(&mut self, data: &[u8]) -> io::Result<()> {
        match self.stream.as_mut() {
            Some(stream) => {
                stream.write(data)?;
            }
            None => {
                let cached = self.cache_data(data);
                warn!("oops!! rx_tcp#{} got {} bytes and cache {} bytes", self.tcp_id, data.len(), cached)
            }
        }
        Ok(())
    }

    fn connection_complete(&mut self, stream: TcpStream) -> io::Result<()> {
        self.stream = Some(stream);
        if self.cache.is_some() {
            let (cache, len) = self.cache.take().unwrap();
            self.stream.as_mut().unwrap().write(&cache[..len])?;
            self.cache = None;
        }
        Ok(())
    }
}

struct TxRuntime {
    poller: Poller<PollObject>,
    fgap_udp_addr: SocketAddr,
    fgap_udp_client: std::net::UdpSocket,
}
impl TxRuntime {
    fn process(&mut self, obj_id: usize, packet: &mut UPacket) {
        trace!("process(), obj_id={}", obj_id);
        let obj_raw = match self.poller.get_object_raw(obj_id) {
            Some(obj_raw) => obj_raw,
            None => {
                warn!("Tx process(obj_id#{}), object not found", obj_id);
                return;
            }
        };
        let obj = Box::leak(unsafe {Box::from_raw(obj_raw as *mut PollObject)});
        let result = match obj {
            PollObject::TcpListener(listener) =>  self.on_listener(listener, packet),
            PollObject::TxTcpSession(tcp) => self.on_tx_tcp_session(tcp, packet),
            PollObject::UdpServer(udp) => self.on_tx_udp(udp, packet),
            PollObject::RxTcpSession(_) => { Ok(()) },
            PollObject::MyReceiver(_) => { Ok(()) },
        };
        if let Err(e) = result {
            error!("TxRuntime process(obj_id#{}) error:{:?}", obj_id, e);
        }
    }

    fn connect(&mut self, tcp_id: usize,  packet: &mut UPacket) -> Result<()> {
        packet.tcp_id = tcp_id as u16;
        packet.flags = TCP_CONNECT;
        packet.data_len = 0;
        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, 8) };
        self.fgap_udp_client.send_to(&buf, &self.fgap_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }

    fn disconnect(&mut self, tcp_id: usize,  packet: &mut UPacket) -> Result<()> {
        packet.tcp_id = tcp_id as u16;
        packet.flags = TCP_DISCONNECT;
        packet.data_len = 0;
        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, 8) };
        self.fgap_udp_client.send_to(&buf, &self.fgap_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }

    fn remove_tcp(&mut self, tcp_id: usize) {
        self.poller.remove_object(tcp_id);
    }

    fn on_listener(&mut self, listener: &mut TcpListener, packet: &mut UPacket) -> Result<()> {
        let stream = listener.accept().chain_err(||"listener.accept()失败")?.0;
        let tcp_id = self.poller.alloc_object_id().ok_or("alloc_object_id() failed")?;
        info!("Tx accept a stream:{:?}", stream);
        let tcp = TxTcpSession {
            tcp_id: tcp_id,
            stream: stream,
        };
        self.connect(tcp.tcp_id, packet)?;
        self.poller.register_object(PollObject::TxTcpSession(tcp), Some(tcp_id)).chain_err(||"注册TcpSession失败")?;
        info!("TxRuntime accept new tx_tcp#{}", tcp_id);
        Ok(())
    }

    fn on_tx_tcp_session(&mut self, tcp: &mut TxTcpSession, packet: &mut UPacket) ->Result<()> {
        let size = tcp.stream.read(&mut packet.data)
            .chain_err(||format!("tx_tcp#{} read data error", tcp.tcp_id))?;
        trace!("tx_tcp#{} read {} bytes", tcp.tcp_id, size);

        if size == 0 {
            info!("tx_tcp#{} disconnected", tcp.tcp_id);
            let _ =self.disconnect(tcp.tcp_id, packet);
            self.remove_tcp(tcp.tcp_id);
            return Ok(())
        }

        packet.tcp_id = tcp.tcp_id as u16;
        packet.flags = 0;
        packet.data_len = size as u32;

        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, size+8) };
        self.fgap_udp_client.send_to(&buf[..], &self.fgap_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }

    fn on_tx_udp(&mut self, udp: &mut UdpSocket, packet: &mut UPacket) -> Result<()> {
        let mut buf = [0 as u8; 64*1024];
        let (size, _peer) = udp.recv_from(&mut buf).chain_err(||"error reading udp_packet")?;

        let raw = &buf as *const _ as usize;
        let upacket = Box::leak(unsafe {Box::from_raw(raw as *mut UPacket)});
        let disconnect_flag: bool = upacket.flags & TCP_DISCONNECT != 0;
        trace!("Tx upacket of tx_tcp#{} received, size={}, flags={}, data_len={}", upacket.tcp_id, size, upacket.flags, upacket.data_len);

        let tcp_id = upacket.tcp_id as usize;
        match self.poller.get_object_mut(tcp_id) {
            Some(obj) => {
                match obj {
                    PollObject::TxTcpSession(tcp) => {
                        let mut err_flag = false;

                        //发送数据;如发送失败则终止TcpSesion
                        if size == upacket.data_len as usize + 8 {
                            if let Err(e) = tcp.stream.write(&upacket.data[..upacket.data_len as usize]) {
                                warn!("tx_tcp# write data error:{:?}", e);
                                err_flag = true;
                            }
                        } else {
                            error!("oops!! tx_tcp#{} udp data corrupted, udp_size={}, data_len={}", tcp_id, size, upacket.data_len);
                        }

                        //若TcpSession已终止,移除相关数据
                        if disconnect_flag {
                            self.remove_tcp(tcp_id);
                            info!("tx_tcp#{} terminated", tcp_id);
                        } else if err_flag {
                            let _ = self.disconnect(tcp_id, packet);
                            self.remove_tcp(tcp_id);
                            info!("tx_tcp#{} terminated", tcp_id);
                        }
                    }
                    _ => {
                        error!("oops!! obj(id={}) is not a RxTcpSession", upacket.tcp_id);
                    }
                }
            }
            None => {
                error!("oops!! tx_tcp#{} not found, notifying peer to disconnect", upacket.tcp_id);
                let _ = self.disconnect(tcp_id, packet);
            }
        }

        Ok(())
    }
}

/* 1. listen on local_tcp_port to accept CLIENT tcp connection
 * 2. read data from accepted tcp connection, and transform the data into udp_data_packet
 * 3. send udp_data_packet to A_FGAP_ip/A_FGAP_udp_port
 * 4. receive response udp_data_packet sent from B_FGAP to local:local_udp_port
 * 5. extract data from udp_data_packet and send it back to CLIENT through tcp_connection
 */
fn run_tx(
    local_udp_port:u16, 
    a_fgap_host_port:&str, 
    local_tcp_port:u16, 
) -> Result<()> {
    let local_tcp_addr: SocketAddr = format!("[::]:{}",local_tcp_port).parse().chain_err(||"解释TcpListener地址失败")?;
    let local_udp_addr: SocketAddr = format!("[::]:{}",local_udp_port).parse().chain_err(||"解释UdpServer地址失败")?;
    let fgap_udp_addr: SocketAddr = a_fgap_host_port.parse().chain_err(||"解释光闸地址失败")?;

    let listener = TcpListener::bind(&local_tcp_addr).chain_err(||"创建TcpListener失败")?;
    let udp_server = UdpSocket::bind(&local_udp_addr).chain_err(||"创建UdpServer失败")?;

    let mut rt = TxRuntime {
        poller: Poller::new(),
        fgap_udp_client: std::net::UdpSocket::bind("[::]:0").chain_err(||"绑定UDP地址失败")?,
        fgap_udp_addr: fgap_udp_addr,
    };

    rt.poller.register_object(PollObject::TcpListener(listener), None)?;
    rt.poller.register_object(PollObject::UdpServer(udp_server), None)?;

    let mut events = Events::with_capacity(1024);
    let mut packet = UPacket::new();
    loop {
        rt.poller.poll.poll(&mut events, None).chain_err(||"Tx poll()失败")?;
        for event in events.iter() {
            match event.token() {
                Token(obj_id) => rt.process(obj_id, &mut packet),
            }
        }
    }
}

struct RxRuntime {
    poller: Poller<PollObject>,
    tcp_server_addr: SocketAddr,
    fgap_udp_addr: SocketAddr,
    fgap_udp_client: std::net::UdpSocket,
    object_sender: MySender,
}
impl RxRuntime {
    fn process(&mut self, obj_id: usize, packet: &mut UPacket) {
        trace!("RxRuntime::process(), obj_id={}", obj_id);
        let obj_raw = match self.poller.get_object_raw(obj_id) {
            Some(obj_raw) => obj_raw,
            None => {
                warn!("Rx process(obj_id#{}), object not found", obj_id);
                return;
            }
        };
        let obj = Box::leak(unsafe {Box::from_raw(obj_raw as *mut PollObject)});
        let result = match obj {
            PollObject::TcpListener(_) => { Ok(()) }, //unreachable!
            PollObject::TxTcpSession(_) => { Ok(()) }, //unreachable!
            PollObject::RxTcpSession(tcp) => self.on_rx_tcp_session(tcp, packet),
            PollObject::UdpServer(udp) => self.on_rx_udp(udp, packet),
            PollObject::MyReceiver(receiver) => self.on_channel_receiver(receiver, packet),
        };
        if let Err(e) = result {
            error!("RxRuntime process(obj_id#{}) error:{:?}", obj_id, e);
        }
    }

    fn remove_tcp(&mut self, tcp_id: usize) {
        self.poller.remove_object(tcp_id);
    }

    fn disconnect(&mut self, tcp_id: usize,  packet: &mut UPacket) -> Result<()> {
        packet.tcp_id = tcp_id as u16;
        packet.flags = TCP_DISCONNECT;
        packet.data_len = 0;
        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, 8) };
        self.fgap_udp_client.send_to(&buf, &self.fgap_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }

    fn on_channel_receiver(&mut self, receiver: &mut MyReceiver, packet: &mut UPacket) -> Result<()> {
        let (tcp_id,stream): (usize, Option<std::net::TcpStream>)  = receiver.recv_object()?;
        match self.poller.get_object_mut(tcp_id) {
            None => {
                error!("on_channel_receiver(), tx_tcp#{} not registered, mabye peer has disconnected.", tcp_id);
                //do nothing
            }
            Some(obj) => {
                match obj {
                    PollObject::RxTcpSession(tcp) => {
                        match stream {
                            Some(stream) => {
                                let result = mio::net::TcpStream::from_stream(stream).and_then(|mstream|{
                                    self.poller.poll.register(&mstream, Token(tcp_id), Ready::readable(), PollOpt::level())?;
                                    tcp.connection_complete(mstream)
                                });
                                if result.is_err() {
                                    let _ = self.disconnect(tcp_id, packet);
                                    self.remove_tcp(tcp_id);
                                }
                                info!("Rx accept new rx_tcp#{} ok", tcp_id);
                            },
                            None => {
                                warn!("Rx rx_tcp#{} connect tcp_server failed, aborting connection.", tcp_id);
                                let _ = self.disconnect(tcp_id, packet);
                                self.remove_tcp(tcp_id);
                            }
                        }
                    }
                    _ => {
                        error!("error!! obj_id={} is not a rx_tcp.", tcp_id);
                    }
                }
            }
        }
        Ok(())
    }

    fn async_connect(&self, tcp_id:usize) {
        let sender = self.object_sender.clone();
        let addr = self.tcp_server_addr.clone();
        task::Builder::new()
            .name("tcp_connect_task".to_string())
            .spawn(async move {
                let stream = match std::net::TcpStream::connect(&addr) {
                    Ok(stream) => Some(stream),
                    Err(_) => None,
                };
                if let Err(e) = sender.send_object((tcp_id, stream)) {
                    //todo::serious problem, something wrong with sender, unrecoverable
                    error!("oops!! async_connect(), send_object for tx_tcp#{} failed, error:{:?}", tcp_id, e);
                }
            }).unwrap();
    }

    fn on_rx_udp(&mut self, udp: &mut UdpSocket, packet: &mut UPacket) -> Result<()> {
        let mut buf = [0 as u8; 64*1024];
        let (size, _peer) = udp.recv_from(&mut buf).chain_err(||"error reading udp_packet")?;

        let raw = &buf as *const _ as usize;
        let upacket = Box::leak(unsafe {Box::from_raw(raw as *mut UPacket)});
        let connect_flag: bool = upacket.flags & TCP_CONNECT != 0;
        let mut disconnect_flag: bool = upacket.flags & TCP_DISCONNECT != 0;
        trace!("Rx upacket of rx_tcp#{} received, size={}, flags={}, data_len={}", upacket.tcp_id, size, upacket.flags, upacket.data_len);

        let tcp_id = upacket.tcp_id as usize;
        let obj = self.poller.get_object_mut(tcp_id);

        if connect_flag { //a new connection
            trace!("rx_tcp#{} request to connect, obj.is_some()={}", tcp_id, obj.is_some());
            if obj.is_some() {
                //todo:: what if conflict with non-tcp object?
                warn!("conflict!! new incoming tx_tcp#{} conflict with existing object, remove the existing", tcp_id);
                self.remove_tcp(tcp_id);
            }
            let tcp_id = upacket.tcp_id as usize;
            let new_tcp = RxTcpSession {
                tcp_id: tcp_id,
                stream: None,
                cache: None,
            };
            self.poller.place_object(PollObject::RxTcpSession(new_tcp), tcp_id).chain_err(||"注册TcpSession失败")?;
            self.async_connect(tcp_id);
            return Ok(())
        }

        match obj {
            Some(obj) => {
                match obj {
                    PollObject::RxTcpSession(tcp) => {
                        if size == upacket.data_len as usize + 8 {
                            if let Err(e) = tcp.process_data(&upacket.data[..upacket.data_len as usize]) {
                                warn!("rx_tcp# write data error:{:?}", e);
                                let _ = self.disconnect(tcp_id, packet);
                                disconnect_flag = true;
                            }
                        } else {
                            error!("oops!! rx_tcp#{} data corrupted, upacket_size={}, data_len={}", tcp.tcp_id, size, upacket.data_len);
                        }
                        if disconnect_flag {
                            self.remove_tcp(tcp_id);
                            info!("rx_tcp#{} terminated", tcp_id);
                        }
                    }
                    _ => {
                        error!("oops!! obj#{} is not a rx_tcp", upacket.tcp_id);
                    }
                }
            }
            None => {
                error!("oops!! rx_tcp#{} not found, notifying peer to disconnect", upacket.tcp_id);
                let _ = self.disconnect(tcp_id, packet);
            }
        }

        Ok(())
    }

    fn on_rx_tcp_session(&mut self, tcp: &mut RxTcpSession, packet: &mut UPacket) ->Result<()> {
        let size = tcp.stream.as_mut().unwrap().read(&mut packet.data)
            .chain_err(||format!("rx_tcp#{} read data error", tcp.tcp_id))?;
        trace!("rx_tcp#{} read {} bytes", tcp.tcp_id, size);
        if size == 0 {
            info!("rx_tcp#{} disconnected", tcp.tcp_id);
            let _ = self.disconnect(tcp.tcp_id, packet);
            self.remove_tcp(tcp.tcp_id);
            return Ok(())
        }

        packet.tcp_id = tcp.tcp_id as u16;
        packet.flags = 0;
        packet.data_len = size as u32;

        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, size+8) };
        self.fgap_udp_client.send_to(&buf[..], &self.fgap_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }
}

/* 1. receive udp_data_packet from A_FGAP
 * 2. if it's a head packet, establish a new tcp_connection to SERVER
 * 3. extract from udp_data_packet and sent it to SERVER through tcp_connection
 * 4. receive response data from SERVER, and transform the data into udp_data_packet
 * 5. send the udp_data_packet to B_FGAP_ip/B_FGAP_port
 */
fn run_rx(
    local_udp_port:u16,
    b_fgap_host_port:&str, 
    tcp_server_host_port:&str,
) -> Result<()> {
    let local_udp_addr: SocketAddr = format!("[::]:{}",local_udp_port).parse().chain_err(||"解释udp_listen地址失败")?;
    let fgap_udp_addr: SocketAddr = b_fgap_host_port.parse().chain_err(||"解释fgap地址失败")?;
    let tcp_server_addr: SocketAddr = tcp_server_host_port.parse().chain_err(||"解释tcp_server地址失败")?;

    let udp_server = UdpSocket::bind(&local_udp_addr).chain_err(||"创建UdpServer失败")?;
    let (sender, receiver) = mychannel::channel().chain_err(||"创建MyChannel失败")?;

    let mut rt = RxRuntime {
        poller: Poller::new(),
        tcp_server_addr: tcp_server_addr,
        fgap_udp_client: std::net::UdpSocket::bind("[::]:0").chain_err(||"绑定UDP地址失败")?,
        fgap_udp_addr: fgap_udp_addr,
        object_sender: sender,
    };

    rt.poller.register_object(PollObject::UdpServer(udp_server), None)?;
    rt.poller.register_object(PollObject::MyReceiver(receiver), None)?;

    let mut events = Events::with_capacity(1024);
    let mut packet = UPacket {tcp_id: 0, flags: 0, data_len: 0, data:[0;64*1024-8]};
    loop {
        rt.poller.poll.poll(&mut events, None).chain_err(||"Rx poll()失败")?;
        for event in events.iter() {
            match event.token() {
                Token(obj_id) => rt.process(obj_id, &mut packet),
            }
        }
    }
}

fn usage(prog_name: &str) {
    println!("usage:{} tx -fgap host:port -udp_listen udp_port -tcp_listen tcp_port [-r log_path] [-level log_level]", prog_name);
    println!("usage:{} rx -fgap host:port -udp_listen udp_port -tcp_server host:port [-r log_path] [-level log_level]", prog_name);
    println!(" -fgap host:port              the ip and udp port of A_FGAP to which the program send udp packet");
    println!(" -ludp_listen udp_port        the local udp_port to receive udp packet from B_FGAP");
    println!(" -ltcp_listen tcp_port        the local tcp_port to listen and accept tcp CLIENT");
    println!(" -ltcp_server host:port       the ip and tcp port of SERVER to which the program connect and send data");
    println!(" -r log_path                  the directory to store log files, default to current working path");
    println!(" -level log_level             error|warn|info|debug|trace, default to 'info'");
    std::process::exit(-1);
}
fn main() {
    let mut args = env::args();
    let mut prog_name = args.next().unwrap();
    let pos = match prog_name.rfind('/') {
        Some(pos) => pos+1,
        None => 0,
    };
    prog_name = prog_name.split_at(pos).1.to_string();

    let side = match args.next() {
        Some(val) => {
            if val != "tx" && val != "rx" {
                usage(&prog_name);
            }
            val
        }
        None => {
            usage(&prog_name);
            return;
        }
    };

    let mut local_tcp_port: u16 = 0;
    let mut local_udp_port: u16 = 0;
    let mut fgap_host_port = String::new();
    let mut tcp_server_host_port = String::new();
    let mut log_level = "info".to_string();
    let mut log_dir = env::current_dir().unwrap_or(PathBuf::from("/tmp"));

    loop {
        match args.next() {
            None => {
                break;
            }
            Some(arg) => match arg.as_str() {
                "-r" => {
                    log_dir = args.next()
                        .and_then(|val|{
                            Some(PathBuf::from(val))
                        }).unwrap_or_else(||{
                            eprintln!("invalid -r parameter");
                            usage(&prog_name);
                            log_dir
                        });
                }
                "-log_level" => {
                    log_level = args.next()
                        .and_then(|val|{
                            if val == "error" || val == "warn" || val == "info" || val == "debug" || val == "trace" {
                                Some(val)
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(||{
                            eprintln!("invalid -log_level parameter");
                            usage(&prog_name);
                            log_level
                        });
                }
                "-tcp_server" => {
                    if let Some(val) = args.next() {
                        tcp_server_host_port = val;
                    } else {
                        eprintln!("invalid -tcp_server parameter");
                        usage(&prog_name);
                    }
                }
                "-tcp_listen" => {
                    if let Some(val) = args.next() {
                        local_tcp_port = val.as_str().parse().expect("-tcp_listen tcp_port is not a valid port number");
                    } else {
                        eprintln!("invalid -tcp_listen parameter");
                        usage(&prog_name);
                    }
                }
                "-udp_listen" => {
                    if let Some(val) = args.next() {
                        local_udp_port = val.as_str().parse().expect("-udp_listen udp_port is not a valid port number");
                    } else {
                        eprintln!("invalid -udp_listen parameter");
                        usage(&prog_name);
                    }
                 }
                "-fgap" => {
                    if let Some(val) = args.next() {
                        fgap_host_port = val;
                    } else {
                        eprintln!("invalid -lfgap parameter");
                        usage(&prog_name);
                    }
                 }
                unknown_param => {
                    eprintln!("invalid parameters:{}", unknown_param);
                    usage(&prog_name);
                }
            },
        }
    }

    println!("side={},fgap_host_port={},local_udp_port={},local_tcp_port={},tcp_server_host_port={}",
        side, fgap_host_port, local_udp_port, local_tcp_port, tcp_server_host_port);

    if side == "tx" && (0 == local_udp_port || 0 == fgap_host_port.len() || 0 == local_tcp_port) {
        usage(&prog_name);
    }
    if side == "rx" && (0 == local_udp_port || 0 == fgap_host_port.len() || 0 == tcp_server_host_port.len()) {
        usage(&prog_name);
    }

    flexi_logger::Logger::with_str(&log_level)
        .log_to_file()
        .directory(log_dir)
        .suffix(&side)
        .format(flexi_logger::with_thread)
        .rotate(
            flexi_logger::Criterion::Size(1024*1024*10), 
            flexi_logger::Naming::Numbers, 
            flexi_logger::Cleanup::KeepLogFiles(100)
        )
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    info!("{}_{} running...", prog_name, side);
    if side == "tx" {
        if let Err(e) = run_tx(local_udp_port, &fgap_host_port, local_tcp_port) {
            println!("run_tx() error:{:?}", e);
            std::process::exit(-1);
        }
    } else {
        if let Err(e) = run_rx(local_udp_port, &fgap_host_port, &tcp_server_host_port) {
            println!("run_rx() error:{:?}", e);
            std::process::exit(-1);
        }
    }
}

