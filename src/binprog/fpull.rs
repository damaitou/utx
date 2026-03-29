#[macro_use]
extern crate lazy_static;
extern crate mio;
use mio::unix::EventedFd;
use mio::*;
use mio_extras::timer;

use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, /*Instant*/};
use log::{debug, error, info, trace, warn};

use mylib::config::{ChannelMode, TxConfig, TxFileChannelConfig, SIDE_RX, SIDE_TX};
use mylib::context::{
    self, 
    ThreadAction, 
    ThreadMsg, 
    KIND_CONTROL, 
    KIND_LISTER, 
    KIND_PULLER, 
    KIND_PUSHER, 
    KIND_UTX, 
    KIND_WATCHER, 
    KIND_AGENT
};
use mylib::errors::*;
use mylib::{util, utx};

mod agent_thread;
mod ftp_thread;
mod utx_thread;
mod rt;
mod watch;
mod agent_def;
use crate::agent_thread::AgentWorkQueue;
use crate::ftp_thread::FtpWorkQueue;
use crate::utx_thread::UtxWorkQueue;
use crate::watch::FileChannelWatcher;
use crate::rt::ChannelContainer;

const PUSHSER_PATROL_INTERVAL: u64 = 90;

struct Group {
    side: u32,
    channel: usize,
    status: usize,
    listers: FtpWorkQueue,
    pullers: FtpWorkQueue,
    pushers: FtpWorkQueue,
    utxs: UtxWorkQueue,
    agents: AgentWorkQueue,
    watcher: Option<FileChannelWatcher>,
    poll: &'static Poll,
    //runtime statistics
    iteration: usize,       //how many iterations(LISTER_RUN) since the Group was created
    iteration_files: usize, //how many files processed this iteration
    total_files: usize,     //how many files processed since the Group was created
    bloc_threads: usize,    //how many threads occupied by bloc operation
    scan_interval: u32,     //scan_interval from client_setting
    //last_trigger_time: Instant,
}

impl Drop for Group {
    fn drop(&mut self) {
        info!("dropping Group of channel {}...", self.channel);
        self.stop();
    }
}

impl Group {
    fn new(
        fcc: &TxFileChannelConfig,
        pp: &'static util::ProgParam,
        config: &TxConfig,
        poll: &'static Poll,
    ) -> Result<Group> {
        let mut grp = Group {
            side: config.gc.side,
            channel: fcc.channel,
            status: context::BOOTING,
            listers: FtpWorkQueue::new(fcc.channel),
            pullers: FtpWorkQueue::new(fcc.channel),
            pushers: FtpWorkQueue::new(fcc.channel),
            utxs: UtxWorkQueue::new(fcc.channel, config.gc.do_utx),
            agents: AgentWorkQueue::new(fcc.channel, config.gc.do_utx),
            watcher: None,
            poll: poll,
            iteration: 0,
            iteration_files: 0,
            total_files: 0,
            bloc_threads: 0,
            scan_interval: 1000,
            //last_trigger_time: Instant::now(),
        };

        match &fcc.mode {

            ChannelMode::ClientPullAgent(_cs) => {
                grp.agents.spawn_a_worker(pp, PROG_NAME, KIND_AGENT, config, false)?; //todo
            }

            ChannelMode::ClientPushAgent(_cs) => {},

            ChannelMode::ClientPull(cs) | ChannelMode::ClientPullSftp(cs) => {
                grp.scan_interval = cs.scan_interval;
                grp.utxs.spawn_a_worker(pp, PROG_NAME, context::KIND_UTX, config, false)?; //utx thread,不用关心病毒
                grp.listers.spawn_a_worker(pp, PROG_NAME, context::KIND_LISTER, config)?; //lister thread
                for _i in 0..cs.threads_number as usize {
                    grp.pullers.spawn_a_worker(pp, PROG_NAME, context::KIND_PULLER, config)?;
                }
            }

            ChannelMode::ClientPush(cs) | ChannelMode::ClientPushSftp(cs) => {
                for _i in 0..cs.threads_number as usize {
                    grp.pushers.spawn_a_worker(pp, PROG_NAME, context::KIND_PUSHER, config)?;
                }
                let id = context::calc_thread_id(fcc.channel, KIND_WATCHER, 0);
                let watcher = FileChannelWatcher::new(fcc.channel, &fcc.local_root_path, id)?;
                let raw_fd = &watcher.notify.as_raw_fd();
                grp.watcher = Some(watcher); //file watcher
                poll.register(
                    &EventedFd(raw_fd),
                    Token(id),
                    Ready::readable(),
                    PollOpt::level(),
                )
                .chain_err(|| "在Poll实例中注册INotify监听失败")?;
            }

            ChannelMode::Internal(_) | ChannelMode::Server(_) => {
                if grp.side == SIDE_TX {
                    //对于internal模式的文件utx要负责查杀病毒;server模式的文件由ftpd负责杀毒,utx不用关心
                    let care_about_virus = if let ChannelMode::Internal(_) = fcc.mode {
                        true
                    } else {
                        false
                    };
                    grp.utxs.spawn_a_worker(
                        pp,
                        PROG_NAME,
                        context::KIND_UTX,
                        config,
                        care_about_virus,
                    )?; //utx thread
                    let id = context::calc_thread_id(fcc.channel, KIND_WATCHER, 0);
                    let watcher = FileChannelWatcher::new(fcc.channel, &fcc.local_root_path, id)?;
                    let raw_fd = &watcher.notify.as_raw_fd();
                    grp.watcher = Some(watcher); //file watcher
                    poll.register(
                        &EventedFd(raw_fd),
                        Token(id),
                        Ready::readable(),
                        PollOpt::level(),
                    )
                    .chain_err(|| "在Poll实例中注册INotify监听失败")?;
                }
            }
        }

        Ok(grp)
    }

    fn stop(&mut self) {
        info!("stopping Group channel={}", self.channel);
        let _ = self.listers.stop_workers();
        let _ = self.pullers.stop_workers();
        let _ = self.pushers.stop_workers();
        let _ = self.utxs.stop_workers();
        if let Some(watcher) = self.watcher.as_ref() {
            //经测试mio不会自动deregister FileWatcher,需要显式调用
            let raw_fd = &watcher.notify.as_raw_fd();
            if let Err(e) = self.poll.deregister(&EventedFd(raw_fd)) {
                error!(
                    "channel {} deregistering file watcher error:{:?}",
                    self.channel, e
                );
            }
            self.watcher = None;
        }
        self.status = context::STOPPED;
    }

    fn schedule_lister(&mut self) -> Result<()> {
        self.update_status();
        if self.status == context::RUNNING && !self.listers.is_empty() && self.listers.is_idle(0) {
            if (self.side == SIDE_TX && !self.pullers.is_empty() && self.pullers.is_idle(self.bloc_threads)) || 
               (self.side == SIDE_RX && !self.pushers.is_empty() && self.pushers.is_idle(0))
            {
                //如果本轮没有扫描到文件,休眠scan_interval毫秒;如果扫描到,不休眠立即启动下一轮扫描
                let sleep_millis = if self.iteration_files == 0 {
                    self.scan_interval
                } else {
                    0
                };
                self.iteration += 1;
                self.iteration_files = 0;
                self.listers
                    .comes_a_file(ThreadAction::CmdListerRun, format!("{}", sleep_millis))?;
            }
        }

        Ok(())
    }

    //update_status的作用是把Group从BOOTING状态切换成RUNNING状态
    fn update_status(&mut self) {
        if self.status != context::RUNNING
            && self.listers.is_idle(0)
            && self.pullers.is_idle(self.bloc_threads)
            && self.pushers.is_idle(0)
            && self.utxs.is_idle()
        {
            trace!("update_status(), setting RUNNING...");
            self.status = context::RUNNING;
        }
    }
}

struct RunTime {
    pp: &'static util::ProgParam,
    config: TxConfig,
    poll: &'static mio::Poll,
    listener: UnixListener,
    groups: ChannelContainer<Group>,
    ctrl_stream: Option<UnixStream>,
    timer: timer::Timer<u8>,
}

const PROG_NAME: &'static str = "fpull";
const TOKEN_LISTENER: Token = Token(999999);
const TOKEN_CONTROL: Token = Token(999999 + 1);
const TOKEN_TIMER: Token = Token(999999 + 2);

impl RunTime {
    fn reload_config(&mut self) {
        info!("reloading config...");
        self.config = util::load_config(&self.pp, true, false, false);
        info!("config reloaded ok");
    }

    fn get_group_mut(&mut self, channel: usize) -> Result<&mut Group> {
        let grp = self.groups.get_slot_mut(channel as u8).obj.as_mut().ok_or(
            ErrorKind::UnrecoverableError(
                line!(),
                format!("无法获取channel={}对应的Group对象", channel),
            ),
        )?;
        assert!(grp.channel == channel);
        Ok(grp)
    }

    fn on_timer(&mut self) -> Result<()> {
        //debug!("on_timer() entry.");
        for channel in 0..256 {
            if let Some(grp) = self.groups.get_slot_mut(channel as u8).obj.as_mut() {
                if self.config.gc.side == SIDE_RX {
                    if !grp.pushers.is_empty() && grp.pushers.is_idle(0) {
                        grp.pushers.comes_a_file(ThreadAction::CmdPusherPatrol,"".to_string())?;
                        //grp.last_trigger_time = Instant::now();
                    }
                }
                else if self.config.gc.side == SIDE_TX {
                    if !grp.pullers.is_empty() && grp.pullers.is_idle(grp.bloc_threads) {
                        grp.pullers.comes_a_file(ThreadAction::CmdPullerPatrol,"".to_string())?;
                        //grp.last_trigger_time = Instant::now();
                    }
                }
            }
        }
        Ok(())
    }

    fn on_listener(&mut self) -> Result<()> {
        let (stream, _src) = self.listener.accept().chain_err(|| "accept()连接失败")?;
        info!("on_listener() accept a stream {:?}", stream);

        let msg: ThreadMsg =
            bincode::deserialize_from(&stream).chain_err(|| "on_listener 读取注册请求失败")?;
        debug!("on_listener() receive a thread_msg {:?}", msg);

        match msg.kind {
            KIND_LISTER | KIND_PULLER | KIND_PUSHER | KIND_UTX | KIND_AGENT => {
                let grp = self.get_group_mut(msg.channel)?;
                let raw_fd = &stream.as_raw_fd();
                match msg.kind {
                    KIND_LISTER => grp.listers.accept_worker_stream(msg.id, stream)?,
                    KIND_PULLER => grp.pullers.accept_worker_stream(msg.id, stream)?,
                    KIND_PUSHER => grp.pushers.accept_worker_stream(msg.id, stream)?,
                    KIND_UTX => grp.utxs.accept_worker_stream(msg.id, stream)?,
                    KIND_AGENT => grp.agents.accept_worker_stream(msg.id, stream)?,
                    _ => {}
                }

                self.poll
                    .register(
                        &EventedFd(raw_fd),
                        Token(msg.id),
                        Ready::readable(),
                        PollOpt::level(),
                    )
                    .chain_err(|| "在Poll实例中注册UnixStream失败")?;
            }
            KIND_CONTROL => {
                if self.ctrl_stream.is_none() {
                    let raw_fd = &stream.as_raw_fd();
                    self.ctrl_stream = Some(stream);

                    self.poll
                        .register(
                            &EventedFd(raw_fd),
                            TOKEN_CONTROL,
                            Ready::readable(),
                            PollOpt::level(),
                        )
                        .chain_err(|| "在Poll实例中注册UnixStream失败")?;
                    info!("controller connected from {:?}", self.ctrl_stream);
                } else {
                    warn!("只允许一个控制器连接,不接受第二个连接,drop it");
                    drop(stream);
                }
            }
            _ => {
                warn!("on_listener() encounter an unknown stream, drop it");
                return Ok(());
            }
        }

        Ok(())
    }

    fn ctrl_report(&mut self, mut msg: ThreadMsg, action: ThreadAction, object: &str) -> Result<()> {
        let stream = self
            .ctrl_stream
            .as_ref()
            .ok_or("ctrl_report 获取通信连接失败")?;
        msg.action = action;
        msg.object = object.to_string();
        bincode::serialize_into(stream, &msg).chain_err(|| "ctrl_report 发送序列化对象失败")?;
        Ok(())
    }

    fn on_control(&mut self) -> Result<()> {
        let stream = self
            .ctrl_stream
            .as_ref()
            .ok_or("on_control 获取通信连接失败")?;
        let msg: ThreadMsg =
            bincode::deserialize_from(stream).chain_err(|| "on_control 接收序列化对象失败")?;
        debug!("on_control receive msg:{:?}", msg);
        match msg.action {
            //"RELOAD" => {
            ThreadAction::CtrlReload => {
                self.reload_config();
                self.ctrl_report(msg, ThreadAction::CtrlOk, "configuration reloaded")?;
            }
            //"STOP_FILE_CHANNEL" => {
            ThreadAction::CtrlStopFileChannel => {
                let channel: usize = msg.object.parse().unwrap_or(999);
                if channel < 256 {
                    if let Ok(grp) = self.get_group_mut(channel) {
                        grp.stop();
                        self.ctrl_report(msg, ThreadAction::CtrlOk, "channel has been stopped")?;
                    } else {
                        self.ctrl_report(msg, ThreadAction::CtrlFail, "channel is NOT configured")?;
                    }
                } else {
                    self.ctrl_report(msg, ThreadAction::CtrlFail, "invalid channel number")?;
                }
            }
            //"START_FILE_CHANNEL" => {
            ThreadAction::CtrlStartFileChannel => {
                let channel: usize = msg.object.parse().unwrap_or(999);
                if let Ok(grp) = self.get_group_mut(channel) {
                    if grp.status == context::RUNNING {
                        self.ctrl_report(msg, ThreadAction::CtrlOk, "channel is already running, no operation")?;
                        return Ok(());
                    }
                }

                if let Some(fcc) = self.config.get_fcc(channel) {
                    let grp = Group::new(fcc, &self.pp, &self.config, &self.poll)?;
                    self.groups.place(channel as u8, grp);
                    self.ctrl_report(msg, ThreadAction::CtrlOk, "channel has been started")?;
                } else {
                    self.ctrl_report(msg, ThreadAction::CtrlFail, "channel has no configuration")?;
                }
            }
            //"LIST_FILE_CHANNEL" => {
            ThreadAction::CtrlListFileChannel => {
                let mut info = String::with_capacity(256 * 10);
                for channel in 0..256 {
                    let slot = self.groups.get_slot(channel as u8);
                    match slot.obj.as_ref() {
                        Some(grp) => {
                            info += format!("({},{}),", channel, context::STATUS_NAMES[grp.status])
                                .as_str();
                        }
                        None => {}
                    }
                }
                //self.ctrl_report(msg, "OK", info.as_str())?;
                self.ctrl_report(msg, ThreadAction::CtrlOk, info.as_str())?;
            }
            _ => {
                //self.ctrl_report(msg, "FAIL", "invalid command")?;
                self.ctrl_report(msg, ThreadAction::CtrlFail, "invalid command")?;
            }
        }

        Ok(())
    }

    fn on_lister(&mut self, id: usize, channel: usize, _kind: usize, _index: usize) -> Result<()> {
        let grp = self.get_group_mut(channel)?;
        let msg = grp.listers.get_worker(id).recv()?;
        debug!("on_lister() receive msg:{:?}", msg);
        match msg.action {
            ThreadAction::ThreadReady => {
                grp.listers.comes_a_worker(id)?;
                grp.schedule_lister()?;
            }
            ThreadAction::RspListerFile => {
                grp.iteration_files += 1;
                grp.total_files += 1;
                grp.pullers.comes_a_file(ThreadAction::CmdPullerRun, msg.object)?;
            }
            ThreadAction::RspListerBloc => {
                grp.iteration_files += 1;
                grp.total_files += 1;
                grp.pullers.comes_a_file(ThreadAction::CmdPullerRun, "$B$L$O$C$".to_string())?; //todo
                grp.bloc_threads += 1;
            }
            ThreadAction::ThreadErrorAndExit => {
                //todo
                grp.listers.join_a_worker(id);
            }
            _ => {
                error!("OOPS!!! on_lister() unsupported ThreadAction {:?}",  msg.action);
                //TODO:what should we do?
                grp.listers.comes_a_worker(id)?;
                grp.schedule_lister()?; //TODO:what should we do?
            }
        }

        Ok(())
    }

    fn on_puller(&mut self, id: usize, channel: usize, _kind: usize, _index: usize) -> Result<()> {
        let grp = self.get_group_mut(channel)?;
        let msg = grp.pullers.get_worker(id).recv()?;
        debug!("on_puller() receive msg:{:?}", msg);
        match msg.action {
            ThreadAction::ThreadReady => {
                grp.pullers.comes_a_worker(id)?;
                grp.schedule_lister()?;
            }
            ThreadAction::RspPullerFile => {
                grp.utxs.comes_a_file(ThreadAction::CmdUtxRun, msg.object)?;
                grp.pullers.comes_a_worker(id)?;
                grp.schedule_lister()?;
            }
            ThreadAction::RspPullerBloc => {
                grp.bloc_threads -= 1;
                grp.pullers.comes_a_worker(id)?;
                grp.schedule_lister()?;
            }
            ThreadAction::ThreadErrorAndExit => {
                grp.pullers.join_a_worker(id); //todo
                grp.status = context::DEFUNC; //todo
            }
            _ => {
                error!("OOPS!!! on_puller() unsupported ThreadAction {:?}",  msg.action);
                //TODO:what should we do?
                grp.pullers.comes_a_worker(id)?;
                grp.schedule_lister()?;
            }
        }

        Ok(())
    }

    fn on_pusher(&mut self, id: usize, channel: usize, _kind: usize, _index: usize) -> Result<()> {
        let grp = self.get_group_mut(channel)?;
        let msg = grp.pushers.get_worker(id).recv()?;
        debug!("on_pusher receive msg:{:?}", msg);
        match msg.action {
            ThreadAction::ThreadReady => {
                grp.pushers.comes_a_worker(id)?;
                /*
                if grp.is_idle(0) && grp.last_trigger_time.elapsed().as_secs() >= (PUSHSER_PATROL_INTERVAL+10) {
                    grp.pushers.comes_a_file(ThreadAction::CmdPusherPatrol,"".to_string())?;
                    grp.last_trigger_time = Instant::now();
                }
                */
            }
            ThreadAction::ThreadErrorAndExit => {
                grp.pullers.join_a_worker(id); //todo
            }
            _ => {
                error!("OOPS!!! on_pusher() unsupported ThreadAction {:?}",  msg.action);
                //TODO:what should we do?
                grp.pushers.comes_a_worker(id)?;
            }
        }

        Ok(())
    }

    fn on_agent(&mut self, id: usize, channel: usize, _kind: usize, _index: usize) -> Result<()> {
        let grp = self.get_group_mut(channel)?;
        let msg = grp.agents.get_worker(id).recv()?;
        match msg.action {
            ThreadAction::ThreadReady => {
                grp.agents.comes_a_worker(id)?;
                //grp.schedule_lister()?;
            }
            ThreadAction::ThreadErrorAndExit => {
                grp.agents.join_a_worker(id); //todo
            }
            _ => {
                error!("OOPS!!! on_agent() unsupported ThreadAction {:?}",  msg.action);
                //TODO:what should we do?
                grp.agents.comes_a_worker(id)?;
                //grp.schedule_lister()?;
            }
        }

        Ok(())
    }

    fn on_utx(&mut self, id: usize, channel: usize, _kind: usize, _index: usize) -> Result<()> {
        let grp = self.get_group_mut(channel)?;
        let msg = grp.utxs.get_worker(id).recv()?;
        match msg.action {
            ThreadAction::ThreadReady => {
                grp.utxs.comes_a_worker(id)?;
                grp.schedule_lister()?;
            }
            ThreadAction::ThreadErrorAndExit => {
                grp.utxs.join_a_worker(id); //todo
            }
            _ => {
                error!("OOPS!!! on_utx() unsupported ThreadAction {:?}",  msg.action);
                //TODO:what should we do?
                grp.utxs.comes_a_worker(id)?;
                grp.schedule_lister()?;
            }
        }

        Ok(())
    }

    fn on_watcher(&mut self, id: usize, channel: usize, _kind: usize, _index: usize) -> Result<()> {
        trace!("on_watcher...");
        let grp = self.get_group_mut(channel)?;
        let watcher = grp
            .watcher
            .as_mut()
            .ok_or("fatal: on_watcher() but watcher is null!!!")?;
        assert!(watcher.id == id);

        let mut buffer = [0u8; 4096];
        let events = watcher
            .notify
            .read_events(&mut buffer)
            .chain_err(|| "Failed to read inotify events")?;
        for event in events {
            let event_name = match event.name {
                Some(val) => val,
                None => continue,
            };
            debug!("channel {} file {:?} detected", watcher.channel, event_name);
            let file = match event_name.to_str() {
                Some(name) => name.to_string(),
                None => {
                    error!(
                        "'{:?}' is not a valid unicode file name, skipped",
                        event_name
                    );
                    continue;
                }
            };

            if file.starts_with(".")
                || file.ends_with(".uploading")
                || file.ends_with(".pulling")
                || file.ends_with(".fail_and_retry")
            {
                continue;
            }

            if let Some(detected_file) = watcher.is_file_detected(event.wd, &event.mask, &file) {
                info!("channel {} transfering '{}'...", channel, detected_file);
                grp.iteration_files += 1;
                grp.total_files += 1;
                if SIDE_TX == grp.side {
                    grp.utxs.comes_a_file(ThreadAction::CmdUtxRun, detected_file)?; 
                } else {
                    grp.pushers.comes_a_file(ThreadAction::CmdPusherRun, detected_file)?;
                }
            }
        }

        Ok(())
    }
}

fn run(pp: &'static util::ProgParam, config: TxConfig) -> Result<()> {
    util::init_log(&pp.utx_root, PROG_NAME, &config.gc.log_level)?;
    if pp.daemonize {
        util::daemonize(&pp.utx_root, PROG_NAME)?;
    }

    util::init_audit(
        pp,
        &config.gc.audit_db_conn_string,
        config.file_audit_needed,
    );

    lazy_static! {
        static ref POLL: Poll = match Poll::new() {
            Ok(poll) => poll,
            Err(e) => {
                error!("fatal: Poll::new() failed:{}", e);
                panic!("fatal: Poll::new() failed:{}", e);
            }
        };
    }

    let utx_root = pp.utx_root.clone();
    let mut rt = RunTime {
        pp: pp,
        config: config,
        poll: &POLL,
        listener: util::init_unix_listener(&utx_root, PROG_NAME)?,
        groups: ChannelContainer::new(),
        ctrl_stream: None,
        timer: timer::Timer::default(),
    };

    rt.poll
        .register(
            &EventedFd(&rt.listener.as_raw_fd()),
            TOKEN_LISTENER,
            Ready::readable(),
            PollOpt::level(),
        )
        .chain_err(|| "在Poll实例中注册UnixListener失败")?;

    for fcc in &rt.config.fccs {
        let grp = Group::new(fcc, &rt.pp, &rt.config, &rt.poll)?;
        rt.groups.place(fcc.channel as u8, grp);
    }

    rt.poll
        .register(&rt.timer, TOKEN_TIMER, Ready::readable(), PollOpt::edge())
        .chain_err(|| "register timer failed")?;
    rt.timer.set_timeout(Duration::from_secs(5), 0);

    let mut events = Events::with_capacity(1024);
    loop {
        rt.poll.poll(&mut events, None).chain_err(|| "Poll失败")?;
        for event in events.iter() {
            match event.token() {
                TOKEN_TIMER => {
                    rt.on_timer()?; 
                    rt.timer.set_timeout(Duration::from_secs(PUSHSER_PATROL_INTERVAL), 0);
                }
                TOKEN_LISTENER => { rt.on_listener()?; }
                TOKEN_CONTROL => {
                    if let Err(e) = rt.on_control() {
                        util::log_error(&e);
                        if let Some(stream) = rt.ctrl_stream.take() {
                            let raw_fd = &stream.as_raw_fd();
                            let _ = rt
                                .poll
                                .deregister(&EventedFd(raw_fd))
                                .map_err(|e| error!("deregistering ctrl_stream failed:{}", e));
                        }
                    }
                }
                Token(id) => {
                    let (channel, kind, index) = context::from_thread_id(id);
                    match kind {
                        KIND_LISTER => rt.on_lister(id, channel, kind, index)?,
                        KIND_PULLER => rt.on_puller(id, channel, kind, index)?,
                        KIND_PUSHER => rt.on_pusher(id, channel, kind, index)?,
                        KIND_UTX => rt.on_utx(id, channel, kind, index)?,
                        KIND_WATCHER => rt.on_watcher(id, channel, kind, index)?,
                        KIND_AGENT => rt.on_agent(id, channel, kind, index)?,
                        kind => {
                            error!("receive a unknown id {} of kind {}", id, kind);
                        }
                    }
                }
            }
        }
    }
}

fn main() {
    lazy_static! {
        static ref PP: util::ProgParam = util::parse_args();
    }
    let config = util::load_config(&PP, true, false, false);
    utx::UtxSender::set_tx_mtu(config.gc.mtu);
    utx::UtxSender::set_tx_busy_sleep_nanos(config.gc.tx_busy_sleep_nanos);

    println!("av_needed={}", config.av_needed);
    println!("file_audit_needed={}", config.file_audit_needed);
    println!("clamd_sock_file={}", config.gc.clamd_sock_file);

    if let Err(e) = run(&PP, config) {
        eprintln!("fatal error:{:?}", e);
        error!("fatal error:{:?}, process terminated", e);
        util::log_error(&e);
        std::process::exit(-1);
    }
}
