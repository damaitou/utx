
/* btx: 光闸程序
 *
 *   CLIENT<--(tx_tcp)-->|-------------------------|<--(rx_tcp)-->SERVER
 *                       |-> BTX <--光闸pi--> BTX<-|
 *   SERVER<--(rx_tcp)-->|-------------------------|<--(tx_tcp)-->CLIENT
 *
 */

use std::env;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, IpAddr, /*ToSocketAddrs*/};
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::raw::c_void;
use std::thread;
use std::time::Duration;
use mio::net::{TcpListener, TcpStream, UdpSocket};
use mio::unix::EventedFd;
use mio::*;
use serde::{Serialize, Deserialize};
use async_std::task;
use log::{error, warn, info, debug, trace};
#[macro_use]
extern crate error_chain;

mod config;
mod util;
mod net;
use config::btx_config::*;
use util::mychannel::{self,*};
use util::poller::*;
use util::utx::*;
use util::errors::*;
use util::iptables::*;
use net::proxied_tcp::*;

#[derive(Debug, Clone)]
enum BtxSide {
    UpperHost,      //光闸的上主机
    LowerHost,      //光闸的下主机
}

#[derive(Serialize, Deserialize)]
struct TcpConnectRequest {
    host_port: String,      //eg: 192.168.100.1:1234
}

enum PollObject {
    MyReceiver(MyReceiver),
    TcpListener(TxTcpListener),
    TxTcpSession(TxTcpSession),
    RxTcpSession(RxTcpSession),
    UtxReceiver(UtxReceiver),
}

impl PollableObject for PollObject {
    fn register_me (&self, obj_id:usize, poll:&mio::Poll) -> io::Result<()> {
        let fd: RawFd;
        let ef: EventedFd;
        let evented: &dyn Evented = match self {
            PollObject::TcpListener(l) => &l.inner,
            PollObject::TxTcpSession(t) => &t.stream,
            PollObject::RxTcpSession(t) => {
                match t.stream.as_ref() {
                    Some(stream) => stream,
                    None => {
                        return Err(io::Error::new(std::io::ErrorKind::Other, 
                            format!("register_object(rx_tcp#{}), 尚未建立连接",obj_id)));
                    },
                }
            },
            PollObject::MyReceiver(r) => {
                fd = r.as_raw_fd();
                ef = EventedFd(&fd); 
                &ef 
            }
            PollObject::UtxReceiver(u) => {
                fd =  u.as_raw_fd();
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

struct BtxRuntime {
    side: BtxSide,
    tx_board: usize,
    rx_board: usize,
    config: BtxConfig,
    poller: Poller<PollObject>,
    utx_sender: UtxSender,
    object_sender: MySender,
}
impl BtxRuntime {
    fn process(&mut self, obj_id: usize) {
        let obj_raw = match self.poller.get_object_raw(obj_id) {
            Some(obj_raw) => obj_raw,
            None => {
                error!("Tx process(obj#{}), object not registered", obj_id);
                return;
            }
        };
        let obj = Box::leak(unsafe {Box::from_raw(obj_raw as *mut PollObject)});
        let result = match obj {
            PollObject::TcpListener(listener) => self.on_listener(listener, obj_id),
            PollObject::UtxReceiver(urx) => self.on_utx_receiver(urx),
            PollObject::TxTcpSession(tcp) => self.on_tx_tcp_session(tcp),
            PollObject::RxTcpSession(tcp) => self.on_rx_tcp_session(tcp),
            PollObject::MyReceiver(receiver) => self.on_async_task_complete(receiver),
        };
        if let Err(e) = result {
            error!("Tx process(obj#{}) error:{:?}", obj_id, e);
        }
    }

    #[inline]
    pub fn tcpid_2_sessionid(tcp_id:usize) -> u16 {
        (tcp_id & ((1<<16)-1)) as u16
    }

    fn connect(&self, tcp: &mut TxTcpSession, dst_host_port: &str) -> Result<()> {
        let line:String;
        let buf = match &tcp.app_module {
            TcpAppModule::FtpData => {
                let request = TcpConnectRequest { host_port: dst_host_port.to_string() };
                line = serde_json::to_string(&request).unwrap(); //todo
                Some(line.as_bytes())
            }
            _ => None,
        };

        self.utx_sender.tcp_connect(
            tcp.channel_id, 
            BtxRuntime::tcpid_2_sessionid(tcp.tcp_id), 
            &mut tcp.send_seq,
            buf,
        ); //todo:: deal with the return
        Ok(())
    }

    fn async_connect(&self, tcp_id:usize, addr:SocketAddr) {
        trace!("async_connect(),tcp_id={},addr={:?}", tcp_id, addr);
        let sender = self.object_sender.clone();
        task::Builder::new()
            .name("rx_tcp_connect_task".to_string())
            .spawn(async move {
                let stream = match std::net::TcpStream::connect(&addr) {
                    Ok(stream) => Some(stream),
                    Err(_) => None,
                };
                if let Err(e) = sender.send_object((tcp_id, stream)) {
                    //todo::serious problem, something wrong with sender, unrecoverable
                    error!("oops!! async_connect(), send_object(tx_tcp#{}) failed, error:{:?}", tcp_id, e);
                }
            }).unwrap();
    }

    fn tx_tcp_disconnect(&self, tcp: &mut TxTcpSession) -> Result<()> {
        self.utx_sender.tcp_disconnect(
            tcp.channel_id, 
            BtxRuntime::tcpid_2_sessionid(tcp.tcp_id), 
            &mut tcp.send_seq, 
            UTX_TYPE_TCP_T2R,
        ); //todo:: deal with the return
        Ok(())
    }

    fn tx_tcp_disconnect_by_id(&self, channel:usize, tcp_id: usize) {
        let mut seq: u16 = 0;
        self.utx_sender.tcp_disconnect(
            channel, 
            BtxRuntime::tcpid_2_sessionid(tcp_id), 
            &mut seq, 
            UTX_TYPE_TCP_T2R,
        ); //todo:: deal with the return
    }

    fn rx_tcp_disconnect(&self, tcp: &mut RxTcpSession) -> Result<()> {
        self.utx_sender.tcp_disconnect(
            tcp.channel, 
            BtxRuntime::tcpid_2_sessionid(tcp.tcp_id), 
            &mut tcp.send_seq, 
            UTX_TYPE_TCP_R2T,
        ); //todo:: deal with the return
        Ok(())
    }

    fn rx_tcp_disconnect_by_id(&self, channel:usize, tcp_id: usize) {
        let mut seq: u16 = 0;
        self.utx_sender.tcp_disconnect(
            channel, 
            BtxRuntime::tcpid_2_sessionid(tcp_id), 
            &mut seq, 
            UTX_TYPE_TCP_R2T,
        ); //todo
    }

    fn remove_tcp(&mut self, tcp_id: usize) {
        self.poller.remove_object(tcp_id);
    }

    fn on_utx_receiver(&mut self, urx: &mut UtxReceiver) -> Result<()> {
        urx.loop_on_available_packets(self as *mut _ as *mut c_void);
        Ok(())
    }

    fn on_listener(&mut self, listener: &mut TxTcpListener, obj_id: usize) -> Result<()> {
        let tcp_id = self.poller.alloc_object_id(self.tx_board)
            .ok_or("on_listener() alloc_object_id() failed")?;
        let mut tcp = listener.accept(tcp_id).chain_err(||"TxTcpListern accept failed")?;
        let pass = self.config
                       .get_channel(listener.channel_id as u16)
                       .chain_err(||format!("oops!! channel#{} configuration not found",listener.channel_id))?
                       .check_ip(&tcp.stream.peer_addr().unwrap().ip());
        if !pass {
            warn!("ip({}) try to connect but filtered out.", tcp.stream.peer_addr().unwrap().ip()); //todo
            return Ok(());
        }

        self.connect(&mut tcp, &listener.dst_host_port)?;
        self.poller.register_object(self.tx_board, PollObject::TxTcpSession(tcp), Some(tcp_id))
            .chain_err(||"注册TcpSession失败")?;
        info!("Btx new tx_tcp#{}", tcp_id);

        match listener.app_module {
            TcpAppModule::FtpData => {
                self.poller.remove_object(obj_id); //drop the FtpData Listener right after tcp connection established.
            }
            _ => {}
        }

        Ok(())
    }

    fn on_tx_tcp_session(&mut self, tcp: &mut TxTcpSession) ->Result<()> {
        let mut buf = [0 as u8; 4096];
        let size = tcp.stream.read(&mut buf)
            .chain_err(||format!("tx_tcp#{} read data error", tcp.tcp_id))?;
        trace!("tx_tcp#{} read {} bytes", tcp.tcp_id, size);

        if size == 0 {
            info!("tx_tcp#{} disconnected", tcp.tcp_id);
            let _ =self.tx_tcp_disconnect(tcp);
            self.remove_tcp(tcp.tcp_id);
            return Ok(())
        }

        match tcp.filter_data_input(&buf) {
            FilterInputResult::Pass => {
                self.utx_sender.tcp_send_data(
                    tcp.channel_id, 
                    BtxRuntime::tcpid_2_sessionid(tcp.tcp_id), 
                    &mut tcp.send_seq, 
                    UTX_TYPE_TCP_T2R, 
                    &buf[..size],
                );
            },
            FilterInputResult::DropSilently => {},
            FilterInputResult::DropAndResponse(response) => {
                tcp.stream.write(response.as_bytes())
                    .chain_err(||format!("tx_tcp#{} drop_and_response write data error", tcp.tcp_id))?;
            }
        }
        Ok(())
    }

    fn on_rx_tcp_session(&mut self, tcp: &mut RxTcpSession) ->Result<()> {
        let mut buf = [0 as u8; 4096];
        let size = tcp.stream.as_mut().unwrap().read(&mut buf)
            .chain_err(||format!("rx_tcp#{} read data error", tcp.tcp_id))?;
        trace!("rx_tcp#{} read {} bytes", tcp.tcp_id, size);
        if size == 0 {
            info!("rx_tcp#{} disconnected", tcp.tcp_id);
            let _ = self.rx_tcp_disconnect(tcp);
            self.remove_tcp(tcp.tcp_id);
            return Ok(())
        }

        self.utx_sender.tcp_send_data(
            tcp.channel, 
            BtxRuntime::tcpid_2_sessionid(tcp.tcp_id), 
            &mut tcp.send_seq, 
            UTX_TYPE_TCP_R2T, 
            &buf[..size],
        );
        Ok(())
    }

    fn on_async_task_complete(&mut self, receiver: &mut MyReceiver) -> Result<()> {
        let (tcp_id,stream): (usize, Option<std::net::TcpStream>)  = receiver.recv_object()?;
        match self.poller.get_object_mut(tcp_id) {
            None => {
                //do nothing
                error!("on_async_task_complete(), rx_tcp#{} not registered, mabye peer has disconnected.", tcp_id);
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
                                    let _ = self.rx_tcp_disconnect(tcp);
                                    self.remove_tcp(tcp_id);
                                }
                                info!("Btx accept new rx_tcp#{} ok", tcp_id);
                            },
                            None => {
                                warn!("Btx rx_tcp#{} connect tcp_server failed, aborting connection.", tcp_id);
                                let _ = self.rx_tcp_disconnect(tcp);
                                self.remove_tcp(tcp_id);
                            }
                        }
                    }
                    _ => {
                        error!("error!! obj#{} is not a rx_tcp.", tcp_id);
                    }
                }
            }
        }
        Ok(())
    }

    fn on_tcp_r2t(
        &mut self, 
        channel: usize,
        connect_flag: bool, 
        disconnect_flag: bool, 
        tcp_id: usize,
        data: &[u8],
    ) {
        trace!("on_tcp_r2t(tx_tcp#{}), channel={}, data.len()={}", tcp_id, channel, data.len());
        match self.poller.get_object_mut(tcp_id) {
            Some(obj) => {
                match obj {
                    PollObject::TxTcpSession(tcp) => {
                        //if TxTcpSession has been disconnected, remove it
                        if disconnect_flag {
                            self.remove_tcp(tcp_id);
                            info!("tx_tcp#{} terminated", tcp_id);
                            return;
                        };

                        //let TxTcpSession handle the output data
                        match tcp.on_data_output(data) {
                            Ok(result) => match result {
                                FilterOutputResult::SetupFtpDataChannel((_replaced_response, bl)) => {
                                    self.poller.register_object(self.tx_board, PollObject::TcpListener(bl), None).unwrap(); //todo
                                }
                                _ => {}
                            }
                            Err(e) => {
                                warn!("tx_tcp# write output data error:{:?}", e);
                                let _ = self.tx_tcp_disconnect(tcp);
                                self.remove_tcp(tcp_id);
                                info!("tx_tcp#{} terminated", tcp_id);
                            }
                        }
                    }
                    _ => {
                        error!("oops!! obj#{} is not a tx_tcp", tcp_id);
                    }
                }
            }
            None => {
                error!("oops!! tx_tcp#{} not found", tcp_id);
                if !disconnect_flag {
                    info!("tx_tcp#{} notifying peer to disconnect", tcp_id);
                    let _ = self.tx_tcp_disconnect_by_id(channel, tcp_id);
                }
            }
        } 
    }

    fn on_tcp_t2r(
        &mut self, 
        channel_id: usize,
        connect_flag: bool, 
        disconnect_flag: bool, 
        tcp_id: usize,
        data: &[u8],
    ) {
        trace!("on_tcp_t2r(rx_tcp#{}), channel_id={}, data.len()={}", tcp_id, channel_id, data.len());
        let obj = self.poller.get_object_mut(tcp_id);
        if connect_flag {
            trace!("rx_tcp#{} received connection request", tcp_id);
            if obj.is_some() {
                warn!("oops!! new incoming tx_tcp#{} conflict with existing object, remove the existing", tcp_id);
                self.remove_tcp(tcp_id);
            }

            let line = unsafe { std::str::from_utf8_unchecked(data) }; //todo
            let tcr: TcpConnectRequest = 
                match serde_json::from_str(line) {
                    Ok(tcr) => tcr,
                    Err(e) => {
                        error!("rx_tcp#{} deserialize from utx failed:{:?}", tcp_id, e);
                        error!("rx_tcp#{} rejecting connection...", tcp_id);
                        let _ = self.rx_tcp_disconnect_by_id(channel_id, tcp_id);
                        return;
                    }
                };

            let addr: SocketAddr = 
                match tcr.host_port.parse::<SocketAddr>() {
                    Ok(addr) => addr,
                    Err(e) => {
                        error!("rx_tcp#{} parse '{}' failed:{:?}", tcp_id, tcr.host_port, e);
                        error!("rx_tcp#{} rejecting connection...", tcp_id);
                        let _ = self.rx_tcp_disconnect_by_id(channel_id, tcp_id);
                        return;
                    }
                };

            let new_tcp = RxTcpSession {
                channel: channel_id,
                tcp_id: tcp_id,
                stream: None,
                cache: None,
                send_seq: 0,
                recv_seq: 0,
            };
            match self.poller.place_object(PollObject::RxTcpSession(new_tcp), tcp_id) {
                Ok(_) => self.async_connect(tcp_id, addr),
                Err(e) => {
                    error!("poller注册rx_tcp#{}失败", tcp_id);
                }
            }

            return;
        }

        match obj {
            Some(obj) => {
                match obj {
                    PollObject::RxTcpSession(tcp) => {
                        let mut err_flag = false;
                        if let Err(e) = tcp.process_data(data) {
                            warn!("rx_tcp# write data error:{:?}", e);
                            err_flag = true;
                        }
                        //若TcpSession已终止,移除相关数据
                        if disconnect_flag {
                            self.remove_tcp(tcp_id);
                            info!("rx_tcp#{} terminated", tcp_id);
                        } else if err_flag {
                            let _ = self.rx_tcp_disconnect(tcp);
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
                    let _ = self.rx_tcp_disconnect_by_id(channel_id, tcp_id);
                }
            }
        }
    }

    extern "C" 
    fn on_utx(
        _rt: *mut c_void,
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
        let rt = Box::leak(unsafe {Box::from_raw(_rt as *mut BtxRuntime)});
        let connect_flag: bool = head != 0;
        let disconnect_flag: bool = tail != 0;
        let data = unsafe {std::slice::from_raw_parts(payload, payload_size as usize)};

        match utx_type {
            UTX_TYPE_TCP_T2R => rt.on_tcp_t2r(
                channel as usize, 
                connect_flag, 
                disconnect_flag, 
                session_id as usize | rt.rx_board<<16, 
                &data,
            ),
            UTX_TYPE_TCP_R2T => rt.on_tcp_r2t(
                channel as usize, 
                connect_flag, 
                disconnect_flag, 
                session_id as usize | rt.tx_board<<16, 
                &data,
            ),
            _ => warn!("oops!! unsupported utx_type {}", utx_type),
        }
    }

    fn setup_global_for_tx(&self) -> Result<()> {
        Ok(())
    }

    fn setup_channel_for_tx(&self, channel:&BtxChannel) -> Result<Option<PollObject>> {
        match &channel.protocol {
            BtxProtocol::Tcp(tcp_config) => {
                let listener = match &self.config.general_config.role {
                    BtxRole::Proxy => {
                        let addr = format!("0.0.0.0:{}", tcp_config.proxy_port).parse::<SocketAddr>()
                            .chain_err(||"construct SocketAddr failed")?;
                        let listener = TxTcpListener {
                            channel_id: channel.channel_id as usize,
                            app_module: tcp_config.app_module.clone(),
                            dst_host_port: format!("{}:{}", tcp_config.dst_host, tcp_config.dst_port),
                            inner: TcpListener::bind(&addr)?,
                        };
                        listener
                    }
                    BtxRole::TransparentProxy => {
                        let addr = "127.0.0.0:0".parse::<SocketAddr>()
                            .chain_err(||"construct SocketAddr failed")?;
                        let listener = TxTcpListener {
                            channel_id: channel.channel_id as usize,
                            app_module: tcp_config.app_module.clone(),
                            dst_host_port: format!("{}:{}", tcp_config.dst_host, tcp_config.dst_port),
                            inner: TcpListener::bind(&addr)?,
                        };
                        let listen_port = listener.inner.local_addr().unwrap().port();
                        if !iptables_append_dnat(&tcp_config.dst_host, tcp_config.proxy_port, "127.0.0.1", listen_port) {
                            None.ok_or("setup_channel_for_tx() setting iptable_append_dnat() failed.")?;
                        }
                        listener
                    }
                    BtxRole::Router => {
                        warn!("Router not supported yet");
                        return Ok(None);
                    }
                };
                Ok(Some(PollObject::TcpListener(listener)))
            }
            _ => {
                Ok(None)
            }
        }
    }

    fn setup_channel_for_rx(&self, channel:&BtxChannel) -> Result<Option<PollObject>> {
        Ok(None)
    }
}

/* 1. listen on local_tcp_port to accept CLIENT tcp connection
 * 2. read data from accepted tcp connection, and transform the data into udp_data_packet
 * 3. send udp_data_packet to A_FGAP_ip/A_FGAP_udp_port
 * 4. receive response udp_data_packet sent from B_FGAP to local:local_udp_port
 * 5. extract data from udp_data_packet and send it back to CLIENT through tcp_connection
 */
fn btx_run(side: &BtxSide, config: &BtxConfig) {
    for pi in &config.physical_interfaces {
        let thread_side = side.clone();
        let thread_config = config.clone();
        let thread_pi = pi.clone();
        let pi_index = pi.pi_index;
        let builder = thread::Builder::new();
        let _handle = builder
            .name(format!("tx_pi_{}", thread_pi.pi_index))
            .spawn(move||{
                if let Err(e) = btx_run_a_physical_interface(thread_side, thread_config, thread_pi) {
                    error!("tx_pi_{} encounter unrecoverable error:{:?}", pi_index, e);
                    error!("tx_pi_{} exitting...", pi_index);
                }
            }).unwrap();
    }
}
fn btx_run_a_physical_interface(side:BtxSide, config: BtxConfig, pi: PhysicalInterface,) -> Result<()> {
    //todo::error message should be more detailed
    let (my_mac, peer_mac) = match side {
        BtxSide::UpperHost => (&pi.upper_mac, &pi.lower_mac),
        BtxSide::LowerHost => (&pi.lower_mac, &pi.upper_mac),
    };
    let utx_sender = UtxSender::new(my_mac, peer_mac).chain_err(||"创建UtxSender失败")?;
    let utx_receiver = UtxReceiver::new(my_mac, Some(BtxRuntime::on_utx)) .chain_err(||"创建UtxReceiver失败")?;
    let (sender, receiver) = mychannel::channel().chain_err(||"创建MyChannel失败")?;

    let (tx_board, rx_board) = 
        match side {
            BtxSide::UpperHost => (0, 1),
            BtxSide::LowerHost => (1, 0),
        };

    let mut rt = BtxRuntime {
        side: side,
        tx_board: tx_board,
        rx_board: rx_board,
        config: config,
        poller: Poller::new(2), //2 boards, tx_board for tx_tcp,listener,utx,mychannel,etc; rx_board for rx_tcp
        utx_sender: utx_sender,
        object_sender: sender,
    };

    rt.setup_global_for_tx()?; //global setup like arp

    for channel in &rt.config.channels {
        if channel.pi_index != pi.pi_index {
            continue;
        }
        let obj = match rt.side {
            BtxSide::UpperHost => {
                match channel.direction {
                    BtxDirection::UpperToLower => rt.setup_channel_for_tx(channel)?,
                    BtxDirection::LowerToUpper => rt.setup_channel_for_rx(channel)?,
                }
            }
            BtxSide::LowerHost => {
                match channel.direction {
                    BtxDirection::UpperToLower => rt.setup_channel_for_rx(channel)?,
                    BtxDirection::LowerToUpper => rt.setup_channel_for_tx(channel)?,
                }
            }
        };
        match obj {
            Some(obj) => {
                rt.poller.register_object(rt.tx_board, obj, None)?;
            }
            None => {},
        }
    }

    rt.poller.register_object(rt.tx_board, PollObject::UtxReceiver(utx_receiver), None)?;
    rt.poller.register_object(rt.tx_board, PollObject::MyReceiver(receiver), None)?;

    let mut events = Events::with_capacity(1024);
    loop {
        rt.poller.poll.poll(&mut events, None).chain_err(||"Tx poll()失败")?;
        for event in events.iter() {
            match event.token() {
                Token(obj_id) => rt.process(obj_id),
            }
        }
    }
}

fn usage(prog_name: &str) {
    println!("usage:{} upper [-r utx_root] [-f config_file] [-d]", prog_name);
    println!("usage:{} lower [-r utx_root] [-f config_file] [-d]", prog_name);
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

    let (side, side_string) = match args.next() {
        Some(val) =>  match val.as_str() {
            "upper" => (BtxSide::UpperHost, val),
            "lower" => (BtxSide::LowerHost, val),
            _ => {
                usage(&prog_name);
                return;
            }
        }
        None => {
            usage(&prog_name);
            return;
        }
    };

    let mut utx_root = env::var("UTX_ROOT").unwrap_or(env::var("HOME").unwrap_or("".to_string()));
    let mut config_file = String::new();
    let mut daemonize = false;

    loop {
        match args.next() {
            None => {
                break;
            }
            Some(arg) => match arg.as_str() {
                "-d" => {
                    daemonize = true;
                }
                "-f" => {
                    config_file = args.next()
                        .and_then(|val| Some(val) )
                        .unwrap_or_else(||{
                            eprintln!("invalid -f parameter");
                            usage(&prog_name);
                            config_file
                        });
                }
                "-r" => {
                    utx_root = args.next()
                        .and_then(|val| Some(val) )
                        .unwrap_or_else(||{
                            eprintln!("invalid -r parameter");
                            usage(&prog_name);
                            utx_root
                        });
                }
                unsupported_param => {
                    eprintln!("invalid parameters:{}", unsupported_param);
                    usage(&prog_name);
                }
            },
        }
    }

    if config_file.len() == 0 && utx_root.len() != 0 {
        config_file = format!("{}/utx/etc/btx.json",utx_root);
    }

    println!("side={},utx_root={},config_file={},daemonize={}", side_string, utx_root, config_file, daemonize);

    if config_file.len() == 0 || utx_root.len() == 0 {
        usage(&prog_name);
    }

    let config = match BtxConfig::new(&config_file) {
        Ok(c) => c,
        Err(e) => {
            println!("loading configuration error:{:?}", e);
            std::process::exit(-1);
        }
    };

    //flexi_logger::Logger::with_str(&config.gc.log_level)
    flexi_logger::Logger::with_str("trace")
        .log_to_file()
        .directory(format!("{}/{}", utx_root, "/utx/log/"))
        .suffix(&side_string)
        .format(flexi_logger::with_thread)
        .rotate(
            flexi_logger::Criterion::Size(1024*1024*10), 
            flexi_logger::Naming::Numbers, 
            flexi_logger::Cleanup::KeepLogFiles(100)
        )
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    UtxReceiver::set_rx_mtu(8000);
    UtxSender::set_tx_mtu(8000);

    btx_run(&side, &config);
    info!("{}_{} running...", prog_name, side_string);

    loop {
        thread::sleep(Duration::from_secs(10));
    }
}

