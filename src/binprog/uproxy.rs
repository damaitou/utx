
/* uproxy: a tcp proxy over udp
 *
 *                                  |--(udp)-->A_FGAP--(udp)-->
 *                                  |                         |
 *   CLIENT <-(tx_tcp/udp/sctp)-->UPROXY                   UPROXY<-(rx_tcp/udp/sctp)-->SERVER
 *                                  |                         |
 *                                  |<--(udp)--B_FGAP<-(udp)<-|
 *
 */

use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr};
use std::net::ToSocketAddrs;
use std::os::unix::io::{RawFd, AsRawFd};
use log::{error, warn, info, debug, trace};
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::unix::EventedFd;
use mio::*;
use async_std::task;
use sctp::{SctpListener, SctpStream};

mod util;
mod uproxy_config;
use util::mychannel::{self,*};
use util::poller::*;
use util::errors::*;
use uproxy_config::*;

const BOARD:usize = 0;

const TCP_CONNECT:u8        = 1<<0; //Tx to Rx signal, request to establish TcpSession, should not carry data
const TCP_DISCONNECT:u8     = 1<<1; //signal to peer that TcpSession has been terminated, should not carry data

const SCTP_CONNECT:u8       = TCP_CONNECT;
const SCTP_DISCONNECT:u8    = TCP_DISCONNECT;

const UDP_HEAD:u8           = 1<<0;
const UDP_TAIL:u8           = 1<<1;

const PROTO_TCP:u8          = 1;
const PROTO_SCTP:u8         = 2;
const PROTO_UDP:u8          = 3;

#[repr(C)]
struct UPacket {
    tcp_id: u16,
    proto: u8,
    flags: u8,
    data_len: u32,
    data:[u8; 64*1024-8],
}
impl UPacket {
    fn new() -> UPacket {
        UPacket {
            tcp_id: 0,
            proto: 0,
            flags: 0,
            data_len: 0,
            data: [0 as u8; 64*1024-8],
        }
    }
}

struct MyTcpListener {
    entry_tcp: UproxyEntryTcp,
    inner: TcpListener,
}

struct MySctpListener {
    entry_sctp: SctpListener,
    inner: SctpListener,
}

enum PollObject {
    MyReceiver(MyReceiver),
    MyTcpListener(MyTcpListener),
    //MySctpListener(MySctpListener),
    TxTcpSession(TxTcpSession),
    RxTcpSession(RxTcpSession),
    TxUdpSession(TxUdpSession),
    RxUdpSession(RxUdpSession),
    UdpServer(UdpSocket),
}

impl PollableObject for PollObject {
    fn register_me (&self, obj_id:usize, poll:&mio::Poll) -> io::Result<()> {
        let fd: RawFd;
        let ef: EventedFd;
        let evented: &dyn Evented = match self {
            PollObject::MyTcpListener(l) => &l.inner,
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
            PollObject::TxUdpSession(u) => &u.udp,
            PollObject::RxUdpSession(u) => &u.udp,
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

struct TxUdpSession {
    udp_id: usize,
    udp: UdpSocket,
    peer_addr: SocketAddr,
}
impl TxUdpSession {
    fn new(entry_udp:UproxyEntryUdp) -> Result<TxUdpSession> {
        let addr = entry_udp.local_host_port.parse::<SocketAddr>().chain_err(||"invalid udp local_host_port")?;
        Ok(TxUdpSession {
            udp_id: 0,
            udp: UdpSocket::bind(&addr).chain_err(||"create TxUdpSession failed")?,
            peer_addr: addr, //todo
        })
    }
}

struct RxUdpSession {
    udp_id: usize,
    udp: UdpSocket,
    peer_addr: SocketAddr,
}

struct TxTcpSession {
    tcp_id: usize,
    stream: TcpStream,
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
                warn!("rx_tcp#{} got {} bytes and cache {} bytes", self.tcp_id, data.len(), cached)
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
    peer_udp_addr: SocketAddr,
    peer_udp_client: std::net::UdpSocket,
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
            PollObject::MyTcpListener(listener) =>  self.on_tcp_listener(listener, packet),
            PollObject::TxTcpSession(tx_tcp) => self.on_tx_tcp_session(tx_tcp, packet),
            PollObject::TxUdpSession(tx_udp) => self.on_tx_udp_session(tx_udp, packet),
            PollObject::UdpServer(udp) => self.on_tx_udp(udp, packet),
            PollObject::RxTcpSession(_) => unreachable!(),
            PollObject::RxUdpSession(_) => unreachable!(),
            PollObject::MyReceiver(_) => unreachable!(),
        };
        if let Err(e) = result {
            error!("TxRuntime process(obj_id#{}) error:{:?}", obj_id, e);
        }
    }

    fn connect(&mut self, tcp_id: usize,  packet: &mut UPacket, target_host_port:&str) -> Result<()> {
        packet.tcp_id = tcp_id as u16;
        packet.flags = TCP_CONNECT;
        unsafe {
            let src = target_host_port.as_bytes();
            let len = std::cmp::min(src.len(), std::mem::size_of::<UPacket>()-8);
            std::ptr::copy(src.as_ptr(), packet.data.as_mut_ptr(), len);
            packet.data_len = src.len() as u32;
        }
        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, packet.data_len as usize + 8) };
        self.peer_udp_client.send_to(&buf, &self.peer_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }

    fn disconnect(&mut self, tcp_id: usize,  packet: &mut UPacket) -> Result<()> {
        packet.tcp_id = tcp_id as u16;
        packet.flags = TCP_DISCONNECT;
        packet.data_len = 0;
        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, 8) };
        self.peer_udp_client.send_to(&buf, &self.peer_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }

    fn remove_tcp(&mut self, tcp_id: usize) {
        self.poller.remove_object(tcp_id);
    }

    /*
    fn on_listener(&mut self, listener: &mut MyListener, packet: &mut UPacket) -> Result<()> {
        match &listener.entry {
            UproxyEntry::Tcp(_) => self.on_listener_tcp(listener, packet),
            UproxyEntry::Sctp(_) => self.on_listener_sctp(listener, packet),
            _ => unreachable!(),
            //UproxyEntry::Udp(_) => self.on_listener_udp(listener, packet),
        }
    }
    */

    fn on_sctp_listener(&mut self, listener: &mut MySctpListener, packet: &mut UPacket) -> Result<()> {
        Ok(()) //TODO
    }

    fn on_tcp_listener(&mut self, listener: &mut MyTcpListener, packet: &mut UPacket) -> Result<()> {
        let stream = listener.inner.accept().chain_err(||"listener.accept()失败")?.0;
        let tcp_id = self.poller.alloc_object_id(BOARD).ok_or("alloc_object_id() failed")?;
        info!("TxRuntime accept a stream:{:?}", stream);
        let tcp = TxTcpSession {
            tcp_id: tcp_id,
            stream: stream,
        };
        self.connect(tcp.tcp_id, packet, &listener.entry_tcp.target_host_port)?;
        self.poller.register_object(BOARD, PollObject::TxTcpSession(tcp), Some(tcp_id)).chain_err(||"注册TxTcpSession失败")?;
        info!("TxRuntime accept new tx_tcp#{}", tcp_id);
        Ok(())
    }

    fn on_tx_udp_session(&mut self, tx_udp: &mut TxUdpSession, upacket: &mut UPacket) -> Result<()> {
        let mut buf = [0; 64*1024]; //64k = max udp size
        match tx_udp.udp.recv_from(&mut buf) {
            Ok((mut amount, peer)) => {
                tx_udp.peer_addr = peer;

                upacket.tcp_id = tx_udp.udp_id as u16;
                upacket.proto = PROTO_UDP;
                upacket.flags = UDP_HEAD;
                let upacket_capacity = 64*1024-8;
                let mut offset = 0;
                while amount > 0 {
                    let n = std::cmp::min(upacket_capacity, amount);
                    upacket.data[..n].copy_from_slice(&buf[offset..offset+n]);
                    upacket.data_len = n as u32;
                    amount -= n;
                    offset += n;
                    if amount == 0  {
                        upacket.flags |= UDP_TAIL;
                    }
                    let tmp = unsafe { std::slice::from_raw_parts(upacket as *const _ as *const u8, n+8) };
                    self.peer_udp_client.send_to(&tmp[..], &self.peer_udp_addr).chain_err(||"error sending udp packet")?;
                }
            },
            Err(e) => {
                error!("on_tx_udp() recv_from() error:{:?}", e);
                return Ok(());
            }
        };
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
        packet.proto = PROTO_TCP;
        packet.flags = 0;
        packet.data_len = size as u32;

        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, size+8) };
        self.peer_udp_client.send_to(&buf[..], &self.peer_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }

    fn on_tx_udp(&mut self, udp: &mut UdpSocket, packet: &mut UPacket) -> Result<()> {
        //let mut buf = [0 as u8; 64*1024];
        let mut buf = unsafe { std::slice::from_raw_parts_mut(packet as *mut _ as *mut u8, 64*1024) };
        let (size, _peer) = udp.recv_from(&mut buf).chain_err(||"error reading udp_packet")?;

        if size != packet.data_len as usize + 8 {
            error!("oops!! on_tx_udp() receive corrupted udp packet, udp_size={}, data_len={}", size, packet.data_len);
            return Ok(());
        }

        /*
        let raw = &buf as *const _ as usize;
        let upacket = Box::leak(unsafe {Box::from_raw(raw as *mut UPacket)});
        */

        match packet.proto {
            PROTO_TCP => self.on_tx_udp_2_tcp(packet),
            PROTO_SCTP => self.on_tx_udp_2_sctp(packet),
            PROTO_UDP => self.on_tx_udp_2_udp(packet),
            _ => Ok(()), //simply drop the packet
        }
    }

    fn on_tx_udp_2_udp(&mut self, upacket: &mut UPacket) -> Result<()> {
        let udp_id = upacket.tcp_id as usize;
        match self.poller.get_object_mut(udp_id) {
            Some(obj) => {
                match obj {
                    PollObject::TxUdpSession(tx_udp) => {
                        tx_udp.udp.send_to(&upacket.data[..upacket.data_len as usize], &tx_udp.peer_addr)
                            .chain_err(||format!("on_tx_udp_2_udp() send_to() failed"))?;
                    }
                    _ => {
                        error!("oops!! obj#{} is not a TxUdpSession", udp_id);
                    }
                }
            }
            None => {
                error!("oops!! tx_udp#{} not found", udp_id);
            }
        }
        Ok(())
    }

    fn on_tx_udp_2_sctp(&mut self, upacket: &mut UPacket) -> Result<()> {
        Ok(()) //TODO
    }

    fn on_tx_udp_2_tcp(&mut self, upacket: &mut UPacket) -> Result<()> {
        let disconnect_flag: bool = upacket.flags & TCP_DISCONNECT != 0;
        trace!("tx_tcp#{} flags={}, data_len={}", upacket.tcp_id, upacket.flags, upacket.data_len);

        let tcp_id = upacket.tcp_id as usize;
        match self.poller.get_object_mut(tcp_id) {
            Some(obj) => {
                match obj {
                    PollObject::TxTcpSession(tcp) => {
                        let mut err_flag = false;

                        //发送数据;如发送失败则终止TcpSesion
                        if let Err(e) = tcp.stream.write(&upacket.data[..upacket.data_len as usize]) {
                            warn!("tx_tcp# write data error:{:?}", e);
                            err_flag = true;
                        }

                        //若TcpSession已终止,移除相关数据
                        if disconnect_flag {
                            self.remove_tcp(tcp_id);
                            info!("tx_tcp#{} terminated", tcp_id);
                        } else if err_flag {
                            let _ = self.disconnect(tcp_id, upacket);
                            self.remove_tcp(tcp_id);
                            info!("tx_tcp#{} terminated", tcp_id);
                        }
                    }
                    _ => {
                        error!("oops!! obj#{} is not a TxTcpSession", tcp_id);
                    }
                }
            }
            None => {
                error!("oops!! tx_tcp#{} not found", tcp_id);
                if !disconnect_flag {
                    info!("tx_tcp#{} notifying peer to disconnect", tcp_id);
                    let _ = self.disconnect(tcp_id, upacket);
                }
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
fn run_tx( config: UproxyConfig,) -> Result<()> {

    if config.entries.len() == 0 {
        None.ok_or("tx端需要配置proxy_entries,请检查配置文件")?;
    }

    let mut rt = TxRuntime {
        poller: Poller::new(1),
        peer_udp_client: std::net::UdpSocket::bind("[::]:0").chain_err(||"创建udp_client失败")?,
        peer_udp_addr: config.udp_peer_host_port.parse().chain_err(||"解释udp_peer_host_port地址失败")?,
    };

    let local_udp_addr: SocketAddr = config.udp_local_host_port.parse().chain_err(||"解释UdpServer地址失败")?;
    let udp_server = UdpSocket::bind(&local_udp_addr).chain_err(||"创建UdpServer失败")?;
    rt.poller.register_object(BOARD, PollObject::UdpServer(udp_server), None)?;

    for entry in &config.entries {
        match entry {
            UproxyEntry::Tcp(entry_tcp) => {
                //let listener = MyListener::new(entry)?;
                //rt.poller.register_object(BOARD, PollObject::MyListener(listener), None)?;
                let addr = entry_tcp.local_host_port.parse::<SocketAddr>().chain_err(||"invalid local_host_port")?;
                let listener = MyTcpListener {
                    entry_tcp: entry_tcp.clone(),
                    inner: TcpListener::bind(&addr).chain_err(||format!("监听{}失败", entry_tcp.local_host_port))?,
                };
                rt.poller.register_object(BOARD, PollObject::MyTcpListener(listener), None)?;
            },
            UproxyEntry::Sctp(entry_sctp) => {
                //let listener = MyListener::new(entry)?;
                //rt.poller.register_object(BOARD, PollObject::MyListener(listener), None)?;
                /*
                let addr = entry_tcp.local_host_port.parse::<SocketAddr>().chain_err(||"invalid local_host_port")?;
                let listener = MyTcpListener {
                    entry_tcp: entry_tcp.clone(),
                    inner: TcpListener::bind(&addr).chain_err(||format!("监听{}失败", entry_tcp.local_host_port))?,
                };
                rt.poller.register_object(BOARD, PollObject::MyTcpListener(listener), None)?;
                */
            },
            UproxyEntry::Udp(entry_udp) => {
                let mut tx_udp = TxUdpSession::new(entry_udp.clone())?;
                let udp_id = rt.poller.alloc_object_id(BOARD).ok_or("alloc_object_id() failed")?;
                tx_udp.udp_id = udp_id;
                rt.poller.register_object(BOARD, PollObject::TxUdpSession(tx_udp), Some(udp_id)).chain_err(||"注册UdpSession失败")?;
                info!("TxRuntime register tx_udp#{}", udp_id);
            }
        }
    }

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
    peer_udp_addr: SocketAddr,
    peer_udp_client: std::net::UdpSocket,
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
            PollObject::MyReceiver(receiver) => self.on_channel_receiver(receiver, packet),
            PollObject::RxTcpSession(rx_tcp) => self.on_rx_tcp_session(rx_tcp, packet),
            PollObject::RxUdpSession(rx_udp) => self.on_rx_udp_session(rx_udp, packet),
            PollObject::UdpServer(udp) => self.on_rx_udp(udp, packet),
            PollObject::MyTcpListener(_) => unreachable!(),
            PollObject::TxTcpSession(_) => unreachable!(),
            PollObject::TxUdpSession(_) => unreachable!(),
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
        self.peer_udp_client.send_to(&buf, &self.peer_udp_addr).chain_err(||"error sending udp packet")?;
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

    fn async_connect(&self, tcp_id:usize, target_host_port: String) {
        let sender = self.object_sender.clone();
        task::Builder::new()
            .name("tcp_connect_task".to_string())
            .spawn(async move {
                let stream = match target_host_port.to_socket_addrs() {
                    Ok(mut addr_iter) => {
                        match addr_iter.next() {
                            Some(addr) => {
                                match std::net::TcpStream::connect(&addr) {
                                    Ok(stream) => Some(stream),
                                    Err(e) => {
                                        error!("async_connect() connect to '{}':{:?}", target_host_port, e);
                                        None
                                    }
                                }
                            }
                            None => {
                                error!("async_connect() target_host_port is null");
                                None
                            }
                        }
                    },
                    Err(e) => {
                        error!("async_connect() parse network address '{}' error:{:?}", target_host_port, e);
                        None
                    }
                };
                if let Err(e) = sender.send_object((tcp_id, stream)) {
                    //todo::serious problem, something wrong with sender, unrecoverable
                    error!("oops!! async_connect() send_object for tx_tcp#{} failed, error:{:?}", tcp_id, e);
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
            let target_host_port = String::from_utf8(upacket.data[..upacket.data_len as usize].to_vec())
                .chain_err(||"rx_tcp retrieve targert_host_port from upacket failed")?;
            trace!("rx_tcp#{} request connection to '{}'", tcp_id, target_host_port);
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
            self.async_connect(tcp_id, target_host_port);
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
                        error!("oops!! obj#{} is not a rx_tcp", tcp_id);
                    }
                }
            }
            None => {
                error!("oops!! rx_tcp#{} not found", tcp_id);
                if !disconnect_flag {
                    info!("rx_tcp#{} notifying peer to disconnect", tcp_id);
                    let _ = self.disconnect(tcp_id, packet);
                }
            }
        }

        Ok(())
    }

    fn on_rx_udp_session(&mut self, rx_udp: &mut RxUdpSession, upacket: &mut UPacket) -> Result<()> {
        let mut buf = [0; 64*1024]; //64k = max udp size
        match rx_udp.udp.recv_from(&mut buf) {
            Ok((mut amount, peer)) => {
                rx_udp.peer_addr = peer;

                upacket.tcp_id = rx_udp.udp_id as u16;
                upacket.proto = PROTO_UDP;
                upacket.flags = 0;
                let upacket_capacity = 64*1024-8;
                let mut offset = 0;
                while amount > 0 {
                    let n = std::cmp::min(upacket_capacity, amount);
                    upacket.data[..n].copy_from_slice(&buf[offset..offset+n]);
                    upacket.data_len = n as u32;
                    amount -= n;
                    offset += n;
                    let tmp = unsafe { std::slice::from_raw_parts(upacket as *const _ as *const u8, n+8) };
                    self.peer_udp_client.send_to(&tmp[..], &self.peer_udp_addr).chain_err(||"error sending udp packet")?;
                }
            },
            Err(e) => {
                error!("on_tx_udp() recv_from() error:{:?}", e);
                return Ok(());
            }
        };
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
        packet.proto = PROTO_TCP;
        packet.flags = 0;
        packet.data_len = size as u32;

        let buf = unsafe { std::slice::from_raw_parts(packet as *const _ as *const u8, size+8) };
        self.peer_udp_client.send_to(&buf[..], &self.peer_udp_addr).chain_err(||"error sending udp packet")?;
        Ok(())
    }
}

/* 1. receive udp_data_packet from A_FGAP
 * 2. if it's a head packet, establish a new tcp_connection to SERVER
 * 3. extract from udp_data_packet and sent it to SERVER through tcp_connection
 * 4. receive response data from SERVER, and transform the data into udp_data_packet
 * 5. send the udp_data_packet to B_FGAP_ip/B_FGAP_port
 */
fn run_rx( config: UproxyConfig,) -> Result<()> {

    let (sender, receiver) = mychannel::channel().chain_err(||"创建MyChannel失败")?;
    let mut rt = RxRuntime {
        poller: Poller::new(1),
        peer_udp_client: std::net::UdpSocket::bind("[::]:0").chain_err(||"创建udp_client失败")?,
        peer_udp_addr: config.udp_peer_host_port.parse().chain_err(||"解释udp_peer_host_port地址失败")?,
        object_sender: sender,
    };

    let local_udp_addr: SocketAddr = config.udp_local_host_port.parse().chain_err(||"解释udp_local_host_port地址失败")?;
    let udp_server = UdpSocket::bind(&local_udp_addr).chain_err(||"创建UdpServer失败")?;
    rt.poller.register_object(BOARD, PollObject::UdpServer(udp_server), None)?;
    rt.poller.register_object(BOARD, PollObject::MyReceiver(receiver), None)?;

    let mut events = Events::with_capacity(1024);
    let mut packet = UPacket::new();
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
    println!("usage:{} tx -f config_file", prog_name);
    println!("usage:{} rx -f config_file", prog_name);
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

    let mut config_file = String::new();

    loop {
        match args.next() {
            None => {
                break;
            }
            Some(arg) => match arg.as_str() {
                "-f" => {
                    config_file = match args.next() {
                        Some(val) => val,
                        None => {
                            eprintln!("invalid -f parameter");
                            usage(&prog_name);
                            return;
                        }
                    }
                }
                unknown_param => {
                    eprintln!("invalid parameter:{}", unknown_param);
                    usage(&prog_name);
                }
            },
        }
    }

    println!("side={},config_file={}", side, config_file);
    if config_file.len() == 0 {
        usage(&prog_name);
    }

    let config = UproxyConfig::new(&config_file).expect("加载配置文件失败");

    flexi_logger::Logger::with_str(&config.log_level)
        .log_to_file()
        .directory(&config.log_path)
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
        if let Err(e) = run_tx(config) {
            println!("run_tx() error:{:?}", e);
            std::process::exit(-1);
        }
    } else {
        if let Err(e) = run_rx(config) {
            println!("run_rx() error:{:?}", e);
            std::process::exit(-1);
        }
    }
}

