
use std::io::{Read, Write};
use std::net::{Ipv6Addr,SocketAddr};
use std::os::unix::net::{UnixStream,UnixListener};
use std::os::unix::io::AsRawFd;
use std::os::raw::c_int;
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use mylib::config::{self, TxConfig, TxDatagramChannelConfig};
use mylib::utx::{self, UtxSender};
use mylib::errors::*;
use mylib::audit;
use mylib::util;
use mylib::context::{self, ThreadAction, ThreadMsg,  KIND_UDP, KIND_CONTROL, KIND_TIMER};
use log::{error, warn, info, debug, trace};

use ringbuf::RingBuffer;

#[link(name = "utx", kind = "static")]
extern "C" {
    fn bind_socket_to_interface(
        s: c_int,
        if_name: *const u8, 
    ) -> c_int;
}

const TOKEN_LISTENER: Token = Token(880);
const TOKEN_TIMER: Token = Token(881);
const TOKEN_CONTROL: Token = Token(891);

#[macro_use]
extern crate lazy_static;
extern crate mio;
use mio::net::{UdpSocket};
use mio::unix::EventedFd;
use mio::*;

mod rt;
use crate::rt::{ChannelContainer};

#[derive(Copy, Clone)]
struct UdpBuf {
    channel: usize,
    size: usize,
    data: [u8;64*1024],
}

const BUFFER_SLOTS:usize = 10240;
struct UdpDataBuffer {
    slots: Vec<UdpBuf>,
    slot_index: usize,
    producer: ringbuf::Producer<u64>, //u64 holding address of a UdpBuf, ie &UdpBuf
}

impl UdpDataBuffer {

    fn new(config: &TxConfig, pi_index:u32) -> Result<UdpDataBuffer> {
        let pi = config.gc.get_physical_interface(pi_index).ok_or(
            ErrorKind::UnrecoverableError(
                line!(), format!("OOPS! pi_index={}没有配置对应的物理通道",pi_index)))?; //unlikely
        debug!("pi_index={},tx_mac={},rx_mac={}", pi_index, pi.tx_mac, pi.rx_mac);

        let utx = UtxSender::new(
            pi.tx_mac.as_str(),
            pi.rx_mac.as_str(),
        ).ok_or(ErrorKind::UnrecoverableError(1,"加载Utx失败".to_string()))?;

        let rb = RingBuffer::<u64>::new(BUFFER_SLOTS);
        let (producer, mut consumer) = rb.split();
        let _ = thread::spawn(move || {
            loop {
                let count = consumer.pop_each(|val|{
                    let slot = Box::leak(unsafe {Box::from_raw(val as *mut UdpBuf)});
                    match utx.send_datagram(slot.channel, &slot.data[..slot.size]) {
                        Ok(()) => {},
                        Err(e) => {
                            error!("channel {} send_datagram failed:{:?}", slot.channel, e);
                        }
                    };
                    true
                }, None);
                if count == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });

        let a_slot = UdpBuf {
            channel: 0,
            size: 0,
            data: [0u8; 64*1024]
        };
        Ok(UdpDataBuffer {
            slots: vec!(a_slot; BUFFER_SLOTS),
            slot_index: 0,
            producer: producer,
        })
    }

    fn current_slot(&mut self) -> &mut UdpBuf {
        &mut (self.slots[self.slot_index])
    }

    fn push_current_slot(&mut self) -> bool {
        if self.producer.is_full() {
            return false;
        }
        else {
            let slot = &(self.slots[self.slot_index]);
            let val = slot as *const UdpBuf as u64;
            if let Err(_) = self.producer.push(val) {
                error!("oops! channel {} push ringbuf failure", slot.channel);
                return false;
            }
            self.slot_index += 1;
            //self.slot_index %= 1024;
            self.slot_index %= BUFFER_SLOTS;
            true
        }
    }
}

struct Group {
    _id: usize,
    _status: usize,
    dcc: TxDatagramChannelConfig,
    udp: Option<UdpSocket>,
    traffic_in: u64,
    traffic_out: u64,
    traffic_packets: u64,
    drop_packets: u64,
    //poll: &'static Poll,
    //for audit
    peer: Option<std::net::SocketAddr>,
    last_audit_time: Instant,
    //for data buffer
    buffer_addr: u64, //address of corresponding UdpDataBuffer
}

impl Group {
    fn new(
        _pp: &util::ProgParam,
        poll: &'static Poll,
        dcc: &TxDatagramChannelConfig, 
        buffer_addr: u64,
    ) -> Result<Group> {

        let ipaddr = std::net::IpAddr::V6(<Ipv6Addr>::new(0, 0, 0, 0, 0, 0, 0, 0)); //todo
        let addr = SocketAddr::new(ipaddr, dcc.port);
        let udp = UdpSocket::bind(&addr)
            .chain_err(||"创建UDP服务失败")?;

        if dcc.bind_interface.len() != 0 {
            let mut c_interface = dcc.bind_interface.clone();
            c_interface.push('\0');
            let fd = udp.as_raw_fd();
            match unsafe { bind_socket_to_interface(fd, c_interface.as_ptr()) } {
                0 => {},
                _ => {
                    error!("报文通道{}:bind_socket_to_interface('{}') failed.", dcc.channel, dcc.bind_interface);
                    return None.ok_or(
                        ErrorKind::UnrecoverableError(line!(),format!("绑定网卡'{}'失败",dcc.bind_interface)))?;
                },
            }
        }

        if let Some(rcvbuf_size) = dcc.rcvbuf_size.as_ref() {
            if !util::set_so_rcvbufforce(udp.as_raw_fd(), *rcvbuf_size) { 
                warn!("set_so_rcvbufforce for datagram channel {} failed", dcc.channel);
            }
        }

        let id = context::calc_thread_id(dcc.channel, KIND_UDP, 0);
        let token = Token(id);
        poll.register(&udp, token, Ready::readable(), PollOpt::level())
            .chain_err(||"在Poll实例中注册UDP服务失败")?;

        let grp = Group{
            _id: id,
            _status: context::RUNNING,
            dcc: dcc.clone(),
            udp: Some(udp),
            traffic_in: 0,
            traffic_out: 0,
            traffic_packets: 0,
            drop_packets: 0,
            //poll: poll,
            peer: None,
            last_audit_time: Instant::now(),
            buffer_addr: buffer_addr,
        };
        Ok(grp)
    }

    fn process(&mut self) -> Result<()> {

        let buffer = Box::leak(unsafe {Box::from_raw(self.buffer_addr as *mut UdpDataBuffer)});
        let slot = buffer.current_slot();

        let (n, peer) = self.udp.as_ref()
            .ok_or("udp is null")?
            .recv_from(&mut slot.data)
            .chain_err(|| format!("channel {} 接收报文错误", self.dcc.channel))?;

        slot.channel = self.dcc.channel;
        slot.size = n;
        self.traffic_in += n as u64;
        self.traffic_packets += 1;

        //地址过滤
        if let Some(ips) = self.dcc.allow_ips.as_ref() {
            if !ips.contains(&peer.ip()) {
                return Ok(()); //todo:: audit_log?
            }
        }

        if self.peer.is_none() || self.last_audit_time.elapsed().as_secs() >= 10 { //todo
            self.peer = Some(peer);
            self.last_audit_time = Instant::now();
        }

        if let Some(wc) = &self.dcc.word_checker {
            if !wc.allow(&slot.data[..n]) {
                error!("channel {} 报文没有通过关键字过滤", self.dcc.channel);
                let time = time::get_time();
                let dar =  audit::DatagramAuditRecord {
                    time_sec: time.sec,
                    time_nsec: time.nsec,
                    channel: self.dcc.channel as u8,
                    vchannel: self.dcc.vchannel,
                    side: audit::AS_TX,
                    event: audit::AE_KEYWORD_CHECK,
                    result: audit::AR_ERROR,
                    result_msg: "报文不符合关键字审查规则".to_string(),
                    ip: self.get_peer_ip(),
                    traffic_in: 0,
                    traffic_out: 0,
                    interval: 0,
                };
                audit::audit_d(&dar);
                return Ok(()); 
            }
        }

        if buffer.push_current_slot() {
            self.traffic_out += n as u64; //todo
        }
        else {
            self.drop_packets += 1; //ringbuffer is full, drop packet
        }

        Ok(())
    }

    /*
    fn stop(&mut self) {
        if self.udp.is_none() {
            warn!("channel {} attempt to stop an non-exist UdpSocket.", self.dcc.channel);
            return;
        }

        if let Some(udp) = self.udp.take() {
            match self.runtime.poll.deregister(&udp) {
                Ok(_) => self.status = context::STOPPED,
                Err(e) => error!("channel {} deregistering UdpSocket error:{:?}", self.dcc.channel, e),
            }
            drop(udp);
        }
    }
    */

    fn get_peer_ip(&self) -> String {
        match self.peer {
            None => "".to_string(),
            Some(peer) => peer.ip().to_string(),
        }
    }
}

fn timer_run(pp: &'static util::ProgParam) {
    if let Err(e) = timer_thread_handler(pp) {
        util::log_error(&e);
        thread::sleep(Duration::from_secs(30));
    }
}

fn timer_thread_handler(pp: &'static util::ProgParam) -> Result<()> 
{
    let mut stream = util::unix_connect(&pp.utx_root, "ds")
        .chain_err(||"timer_thread连接主进程UnixSocket失败")?;

    let msg = ThreadMsg {
        channel: 0,
        kind: KIND_TIMER,
        id: context::calc_thread_id(0, KIND_TIMER, 0),
        action: ThreadAction::TimerInit,
        object: "".to_string(),
    };
    bincode::serialize_into(&stream, &msg).chain_err(||"发送序列化对象失败")?;

     loop {
        stream.write(b"time's up")
            .chain_err(||{"timer_thread发送定时信息失败"})?;
        thread::sleep(Duration::from_secs(config::FLOW_STATISTICS_INTERVAL.into()));
    }
}

struct Runtime {
    pp: &'static util::ProgParam,
    config: TxConfig,
    poll: &'static Poll,
    groups: ChannelContainer<Group>,
    listener: UnixListener,
    timer_stream: Option<UnixStream>,
    ctrl_stream: Option<UnixStream>,
    buffers: HashMap<u32, UdpDataBuffer>,
}

impl Runtime {

    fn new(pp: &'static util::ProgParam, config: TxConfig) -> Result<Runtime> {

        lazy_static! {
            static ref POLL: Poll = match mio::Poll::new() {
                Ok(poll) => poll,
                Err(e) => {
                    error!("fatal: Poll::new() failed:{}", e);
                    panic!("fatal: Poll::new() failed:{}", e);
                }
            };
        }

        let utx_root = pp.utx_root.clone();
        let mut rt = Runtime {
            pp: pp,
            config: config,
            poll: &POLL,
            groups: ChannelContainer::new(),
            listener: util::init_unix_listener(&utx_root, "ds")?,
            timer_stream: None,
            ctrl_stream: None,
            buffers: HashMap::new(),
        };

        for dcc in &rt.config.dccs {
            if rt.buffers.get(&dcc.pi_index).is_none() {
                rt.buffers.insert(dcc.pi_index, UdpDataBuffer::new(&rt.config, dcc.pi_index)?);
            }
        }

        Ok(rt)
    }

    fn reload_config(&mut self) {
        eprintln!("reloading config..."); 
        self.config = util::load_config(&self.pp, false, true, false);
    }

    fn get_group_mut(&mut self, channel: usize) -> Result<&mut Group> {
        let grp = self.groups.get_slot_mut(channel as u8).obj.as_mut()
            .ok_or(ErrorKind::UnrecoverableError(line!(), 
                format!("无法获取channel={}对应的Group对象", channel)))?;
        assert!(grp.dcc.channel == channel);
        Ok(grp)
    }

    fn on_listener(&mut self) -> Result<()> {
        let (stream,_src) = self.listener.accept()
            .chain_err(||"accept()连接失败")?;
        trace!("on_listener() accept a stream {:?}", stream);

        let msg: ThreadMsg = bincode::deserialize_from(&stream)
            .chain_err(||"on_listener 读取注册请求失败")?;
        trace!("receive a thread_msg {:?}", msg);

        match msg.kind {
            KIND_CONTROL => {
                if self.ctrl_stream.is_none() {
                    let raw_fd = &stream.as_raw_fd();
                    self.ctrl_stream = Some(stream);
                    self.poll.register(
                        &EventedFd(raw_fd), 
                        TOKEN_CONTROL,
                        Ready::readable(), 
                        PollOpt::level()
                    ).chain_err(||"在Poll实例中注册UnixStream失败")?; 
                } else {
                    warn!("只允许一个控制器连接,不接受第二个连接,dropping connection");
                    drop(stream);
                }
            }
            KIND_TIMER => {
                let raw_fd = &stream.as_raw_fd();
                self.timer_stream = Some(stream);
                self.poll.register(
                    &EventedFd(raw_fd), 
                    TOKEN_TIMER, 
                    Ready::readable(), 
                    PollOpt::level()
                ).chain_err(||"在Poll实例中注册UnixStream失败")?; 
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn on_timer(&mut self) {
        if let Err(e) = self.process_timer() {
            util::log_error(&e);
        }
    }

    fn ctrl_report(&mut self, mut msg: ThreadMsg, action: ThreadAction, object: &str) -> Result<()> {
        let stream = self.ctrl_stream.as_ref().ok_or("ctrl_report 获取通信链接失败")?;
        msg.action = action;
        msg.object = object.to_string();
        bincode::serialize_into(stream, &msg).chain_err(||"ctrl_report 发送序列化对象失败")?;
        Ok(())
    }

    fn on_control(&mut self) -> Result<()> {
        let stream = self.ctrl_stream.as_ref().ok_or("on_control 获取通信链接失败")?;
        let msg:ThreadMsg = bincode::deserialize_from(stream).chain_err(||"on_control 接收序列化对象失败")?;
        trace!("on_control receive msg:{:?}", msg);
        /*
        match msg.action.as_str() {
            "RELOAD" => {
                self.reload_config();
                self.ctrl_report(msg, "OK", "configuration reloaded")?;
            }
            "STOP_DATAGRAM_CHANNEL" => {
                let channel:usize = msg.object.parse().unwrap_or(999);
                if channel < 256 {
                    if let Ok(grp) = self.get_group_mut(channel) {
                        grp.stop(); 
                        self.ctrl_report(msg, "OK", "channel has been stopped")?;
                    } else {
                        self.ctrl_report(msg, "FAIL", "channel is NOT configured")?;
                    }
                } else {
                    self.ctrl_report(msg, "FAIL", "invalid channel number")?;
                }
            }
            "START_DATAGRAM_CHANNEL" => {
                let channel:usize = msg.object.parse().unwrap_or(999);
                if let Ok(grp) = self.get_group_mut(channel) {
                    if grp.status == context::RUNNING {
                        self.ctrl_report(msg, "OK", "channel is already running, no operation")?;
                        return Ok(());
                    }
                }

                if let Some(dcc) = self.config.get_dcc(channel) {
                    //let grp = Group::new(&self.pp, &self.config, dcc, &self.poll, &self.buffer)?;
                    let grp = Group::new(&self.pp, &self, dcc)?;
                    self.groups.place(channel as u8, grp);
                    self.ctrl_report(msg, "OK", "channel has been started")?;
                } else {
                    self.ctrl_report(msg, "FAIL", "channel has no configuration")?;
                }
            }
            "LIST_DATAGRAM_CHANNEL" => {
                let mut info = String::with_capacity(256*10);
                for channel in 0..256 {
                    let slot = self.groups.get_slot(channel as u8);
                    match slot.obj.as_ref() {
                        Some(grp) => {
                            info += format!("({},{}),", channel, context::STATUS_NAMES[grp.status]).as_str();
                        }
                        None => { }
                    }
                }
                self.ctrl_report(msg, "OK", info.as_str())?;
            }
            _ => {
                self.ctrl_report(msg, "FAIL", "invalid command")?;
            }
        }
        */

        Ok(())
    }

    fn process_timer(&mut self) -> Result<()> {
        match &self.timer_stream.as_ref() {
            Some(mut stream) => {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf).chain_err(||"reading timer_streaming error")?;
                debug!("receive from timer_stream:{}", String::from_utf8_lossy(&buf[..n]));

                for channel in 0..=255 {
                    let slot = self.groups.get_slot_mut(channel);
                    let grp = match &mut slot.obj {
                        Some(grp) => grp,
                        None => continue,
                    };

                    debug!("tx datagram channel {}: traffic_in={}, traffic_out={}, packets={}, drops={}", 
                        grp.dcc.channel, grp.traffic_in, grp.traffic_out, grp.traffic_packets, grp.drop_packets);
                    if grp.dcc.audit && (grp.traffic_in != 0 || grp.traffic_out != 0) {
                        let time = time::get_time();
                        let dar =  audit::DatagramAuditRecord {
                            time_sec: time.sec,
                            time_nsec: time.nsec,
                            channel: grp.dcc.channel as u8,
                            vchannel: grp.dcc.vchannel,
                            side: audit::AS_TX,
                            event: audit::AE_DATAGRAM_STATS,
                            result: audit::AR_OK,
                            result_msg: "".to_string(),
                            ip: grp.get_peer_ip(),
                            traffic_in: grp.traffic_in as i64,
                            traffic_out: grp.traffic_out as i64,
                            interval: config::FLOW_STATISTICS_INTERVAL,
                        };
                        audit::audit_d(&dar);
                    }
                    grp.traffic_in = 0;
                    grp.traffic_out = 0;
                    grp.traffic_packets = 0;
                    grp.drop_packets = 0;
                }
            }
            None => {}
        }

        Ok(())
    }

    fn on_udp(&mut self, id: usize) {
        let (channel, kind, _index) = context::from_thread_id(id);
        assert!(kind == KIND_UDP);
        if let Ok(grp) = self.get_group_mut(channel) {
            if let Err(e) = grp.process() {
                util::log_error(&e);
            }
        } else {
            warn!("on_udp() error, id={}/channel={} can't find group", id, channel);
        }
    }

    fn buffer_addr_of_pi(&self, pi_index:u32) -> Option<u64> {
        if pi_index >= 10 {
            return None;
        }
        self.buffers
            .get(&pi_index)
            .map(|buffer| buffer as *const _ as u64)
    }
}

fn run(pp: &'static util::ProgParam, config: TxConfig) -> Result<()> {

    if config.gc.side != config::SIDE_TX {
        None.ok_or(ErrorKind::UnrecoverableError(line!(),
            "ds程序只能运行在tx端,请检查配置文件的side配置选项".to_string()))?;
    }

    util::init_log(&pp.utx_root, "ds", &config.gc.log_level)?;
    if pp.daemonize {
        util::daemonize(&pp.utx_root, "ds")?;
    }

    util::init_audit(pp, &config.gc.audit_db_conn_string, config.datagram_audit_needed);

    let mut rt = Runtime::new(pp, config)?;

    rt.poll.register(
        &EventedFd(&rt.listener.as_raw_fd()), 
        TOKEN_LISTENER, 
        Ready::readable(), PollOpt::level()
    ).chain_err(||"在Poll实例中注册UnixListener失败")?;

    let mut counter = 0;
    for dcc in &rt.config.dccs {
        //let grp = Group::new(&rt.pp, &rt.config, &dcc, &rt.poll, &rt.buffer)
        let buffer_addr = rt.buffer_addr_of_pi(dcc.pi_index)
            .ok_or(format!("physical_interface {} has no UdpDataBuffer", dcc.pi_index))?;
        let grp = Group::new(&rt.pp, &rt.poll, &dcc, buffer_addr)
            .chain_err(||format!("starting datagram channel {} failed", dcc.channel))?;
        rt.groups.place(dcc.channel as u8, grp);
        counter += 1;
    }

    match counter {
        0 => {
            warn!("没有找到UDP服务配置,没有UDP服务在运行");
            eprintln!("没有找到UDP服务配置,没有UDP服务在运行");
            //std::process::exit(0);
        },
        n => info!("一共创建了{}个UDP服务", n),
    }

    //create timer thread
    let thread_pp = rt.pp;
    let _handle = thread::spawn(move|| {
        timer_run(thread_pp);
    });

    let mut events = Events::with_capacity(1024);
    loop {
        rt.poll.poll(&mut events, None)
            .chain_err(||"poll()失败")?;
        for event in events.iter() {
            match event.token() {
                TOKEN_LISTENER => rt.on_listener()?,
                TOKEN_TIMER => rt.on_timer(),
                TOKEN_CONTROL => {
                    if let Err(e) = rt.on_control() {
                        util::log_error(&e);
                        if let Some(ctrl_stream) = rt.ctrl_stream.take() {
                            let raw_fd = &ctrl_stream.as_raw_fd();
                            let _ = rt.poll.deregister(&EventedFd(raw_fd))
                                .map_err(|e| error!("deregistering ctrl_stream failed:{}", e));
                        }
                    }
                }
                Token(id) =>  rt.on_udp(id),
            }
        }
    }
}

fn main() {
    lazy_static! {
        static ref PP: util::ProgParam = util::parse_args();
    }
    let config = util::load_config(&PP, false, true, false);
    utx::UtxSender::set_tx_mtu(config.gc.mtu);
    utx::UtxSender::set_tx_busy_sleep_nanos(config.gc.tx_busy_sleep_nanos);

    if let Err(e) = run(&PP, config) {
        util::log_error(&e);
        std::process::exit(-1);
    }
}

