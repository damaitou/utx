extern crate bincode;
extern crate serde;

use log::{debug, error, info, warn};
use std::collections::VecDeque;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, SystemTime};
use std::path::Path;

use mylib::audit;
use mylib::config::{
    self, ChannelMode, GeneralConfig, PhysicalInterface, TxConfig, TxFileChannelConfig,
};
use mylib::context::{self, ThreadAction, ThreadMsg, KIND_LISTER, /*KIND_PULLER, KIND_PUSHER*/};
use mylib::errors::*;
use mylib::ftp;
use mylib::sftp;
use mylib::util::{self, log_error};
use mylib::utx;
use mylib::virus;
use mylib::def::*;

struct FtpThreadContext {
    pp: &'static util::ProgParam,
    gc: GeneralConfig,
    fcc: TxFileChannelConfig,
    pi: PhysicalInterface,
    lh: String, //log informaton header
    kind: usize,
    id: usize,
    stream: UnixStream,
    pending_job: Option<ThreadMsg>, //the failed job
    fails: usize,                   //how many times the pending_job has failed
}

impl FtpThreadContext {
    fn send(&self, action: ThreadAction, obj: &str) -> Result<()> {
        let msg = ThreadMsg {
            channel: self.fcc.channel,
            kind: self.kind,
            id: self.id,
            action: action,
            object: obj.to_string(),
        };
        bincode::serialize_into(&self.stream, &msg).chain_err(|| "发送序列化对象失败")?;
        Ok(())
    }

    fn recv(&self) -> Result<ThreadMsg> {
        Ok(bincode::deserialize_from(&self.stream).chain_err(|| "接收序列化对象失败")?)
    }

    fn fails_add(&mut self) {
        self.fails += 1;
    }

    fn fails_clear(&mut self) {
        self.fails = 0;
    }

    fn too_many_fails(&self, to_add: usize) -> bool {
        (self.fails + to_add) > 3
    }
}

pub fn thread_run(
    pp: &'static util::ProgParam,
    prog_name: &str,
    gc: GeneralConfig,
    fcc: TxFileChannelConfig,
    kind: usize,
    id: usize,
    channel: usize,
) -> Result<()> {
    assert!(kind < context::KIND_NAMES.len());

    let mut scanner = match fcc.scan_virus {
        false => None,
        true => Some(virus::VirusScanner::new(&gc.clamd_sock_file)),
    };

    let stream = util::unix_connect(&pp.utx_root, prog_name)?;
    let pi = gc
        .get_physical_interface(fcc.pi_index)
        .ok_or("gc.get_physical_interface() failed")?
        .clone();
    let mut ctx = FtpThreadContext {
        pp: pp,
        gc: gc,
        fcc: fcc,
        pi: pi,
        kind: kind,
        id: id,
        lh: format!( "{}(channel={},id={})", context::KIND_NAMES[kind], channel, id),
        stream: stream,
        pending_job: None,
        fails: 0,
    };

    ctx.send(ThreadAction::ThreadInitOk, "")?; //register

    loop {
        //check Out-Of-Band message
        if util::data_available(ctx.stream.as_raw_fd()) {
            match ctx.recv() {
                Ok(msg) => {
                    info!("{} received out-of-band message:{:?}", ctx.lh, msg);
                    if msg.action == ThreadAction::CmdQuit {
                        info!("{} received 'CmdQuit', thread exit.", ctx.lh);
                        break;
                    }
                }
                Err(e) => {
                    error!("{} read out-of-band message error:{:?}", ctx.lh, e);
                    error!("{} encounter unknown situation, thread exitting...", ctx.lh);
                    break;
                }
            }
        }

        if let Err(e) = ftp_thread_handler(&mut ctx, &mut scanner) {
            util::log_error(&e);
            ctx.fails_add();

            match e.kind() {
                ErrorKind::UnrecoverableError(_, _) => {
                    if let Err(e) = ctx.send(ThreadAction::ThreadErrorAndExit, "") {
                        error!("{} sending 'ThreadErrorAndExit' error:{:?}", ctx.lh, e);
                    }
                    break;
                }
                ErrorKind::RecoverableError(_, _) | _ => {
                    if ctx.too_many_fails(0) {
                        match ctx.pending_job.take() {
                            Some(msg) =>  warn!("{} 连续失败{}次, 放弃当前失败任务{:?}", ctx.lh, ctx.fails, msg),
                            None => warn!("{} 连续失败{}次.", ctx.lh, ctx.fails),
                        };
                        ctx.fails_clear(); //todo::clear fails?
                    } else if ctx.fails > 1 {
                        info!("{} 连续失败{}次,10秒后重试...", ctx.lh, ctx.fails);
                        thread::sleep(Duration::from_secs(10));
                    } else {
                        info!("{} 失败{}次,立刻重试...", ctx.lh, ctx.fails);
                    }
                }
            }
        } else {
            info!("{} terminated normally", ctx.lh);
            break;
        }
    }
    Ok(())
}

fn ftp_thread_handler(
    ctx: &mut FtpThreadContext,
    scanner: &mut Option<virus::VirusScanner>,
) -> Result<()> {
    info!("{} created", ctx.lh);
    let (cs, is_sftp) = match &ctx.fcc.mode {
        ChannelMode::ClientPush(cs) | ChannelMode::ClientPull(cs) => (cs, false),
        ChannelMode::ClientPushSftp(cs) | ChannelMode::ClientPullSftp(cs) => (cs, true),
        _ => unreachable!(), //todo
    };

    let track_peer_files =
        (ctx.kind == KIND_LISTER && cs.remote_ftp_after_treament == config::AR_KEEP)
        || ctx.fcc.file_ext_checker.is_some();

    let mut ftp: Box<dyn FileTransfer> = match is_sftp {
        true => {
            Box::new(sftp::SftpStream::new(&ctx.pp.utx_root, ctx.id, &ctx.fcc, &cs, &ctx.lh, track_peer_files,)
                .map_err(|e| {
                    let alert_msg = format!("建立sftp连接失败:{:?}", e);
                    audit::audit_alert(
                        audit::ALERT_TYPE_FILE,
                        ctx.fcc.channel as u8,
                        ctx.fcc.vchannel,
                        if ctx.gc.side == config::SIDE_TX { audit::AS_TX } else { audit::AS_RX },
                        audit::AE_FTP_CONNECT,
                        alert_msg,
                    );
                    e
                })?)
        }
        false => {
            Box::new(ftp::FtpStream::new(&ctx.pp.utx_root, ctx.id, &ctx.fcc, &cs, &ctx.lh, track_peer_files,)
                .map_err(|e| {
                    let alert_msg = format!("建立ftp连接失败:{:?}", e);
                    audit::audit_alert(
                        audit::ALERT_TYPE_FILE,
                        ctx.fcc.channel as u8,
                        ctx.fcc.vchannel,
                        if ctx.gc.side == config::SIDE_TX { audit::AS_TX } else { audit::AS_RX },
                        audit::AE_FTP_CONNECT,
                        alert_msg,
                    );
                    e
                })?)
        }
    };

    let mut report_ready = true;
    loop {
        let msg = match ctx.pending_job.take() {
            Some(job) => job, //unfinished job of last failure
            None => {
                if report_ready {
                    debug!("{} declaring available", ctx.lh);
                    ctx.send(ThreadAction::ThreadReady, "")?;
                }
                //ctx.fails = 0;
                ctx.recv()?
            }
        };

        if msg.action == ThreadAction::CmdQuit {
            info!("{} received 'CmdQuit', quit.", ctx.lh);
            break;
        }

        let mut do_job = |ctx: &FtpThreadContext| -> Result<()> {
            match msg.action {
                ThreadAction::CmdListerRun => {
                    debug!("lister_run '{}'...", msg.object);
                    let num: u64 = msg.object.parse().unwrap_or(0);
                    if num != 0 {
                        thread::sleep(Duration::from_millis(num));
                    }

                    let cb = Box::new(|file: &str, ty: u8| {
                        if !file.ends_with(".badcontent")
                            && !file.ends_with(".infected")
                            && !file.ends_with(".badfileext")
                            && !file.ends_with(".badfiletype")
                        {
                            if ty == FTP_FILE {
                                ctx.send(ThreadAction::RspListerFile, file)
                            } else if ty == FTP_BLOC {
                                ctx.send(ThreadAction::RspListerBloc, file)
                            } else {
                                Ok(())
                            }
                        } else {
                            Ok(())
                        }
                    });

                    let cbof = CallBackOnListedFile {
                        callback: &cb,
                    };

                    let truncate_empty_directory = cs.remote_ftp_after_treament == config::AR_DELETE_FILE_AND_DIRECTORY; //TODO
                    match ctx.fcc.mode {
                        ChannelMode::ClientPull(_)|ChannelMode::ClientPullSftp(_) => ftp.fetch_dir("", &cbof, 0, truncate_empty_directory)?,
                        ChannelMode::ClientPush(_)|ChannelMode::ClientPushSftp(_) => ftp.put_dir(".", &cbof, 0, truncate_empty_directory)?,
                        _ => {
                            error!("OOPS!!! invalid ftp_mode, Task Aborted!"); //todo
                        }
                    }
                }
                ThreadAction::CmdPullerRun => {
                    info!("puller_run '{}'...", msg.object);
                    /*
                    if msg.object == "$B$L$O$C$" {
                        let us = utx::UtxSender::new(&ctx.pi.tx_mac, &ctx.pi.rx_mac)
                            .ok_or("UtxSender::new() failed.")?;
                        ftp.ftp_fetch_bloc(msg.object.as_str(), &us, &ctx.fcc)?;
                        ctx.send(ThreadAction::RspPullerBloc, &msg.object)?;
                        report_ready = false; //TODO
                    } else {
                    */
                        let fetch_ok = ftp.fetch_file(
                            msg.object.as_str(),
                            &ctx.fcc.word_checker,
                            scanner,
                        )?;
                        if fetch_ok {
                            match cs.remote_ftp_after_treament {
                                config::AR_DELETE_FILE|config::AR_DELETE_FILE_AND_DIRECTORY => {
                                    ftp.rm_file(msg.object.as_str())?;
                                }
                                _ => {} //AR_MOVE not supported
                            };

                            // encode (file_name,peer_ip,ftp_user) and send out
                            let file_ip_user = format!(
                                "{}\0{}\0{}",
                                msg.object,
                                ftp.peer_addr().ip().to_string(),
                                cs.remote_ftp_user
                            );
                            ctx.send(ThreadAction::RspPullerFile, &file_ip_user)?;
                        }
                        report_ready = !fetch_ok;
                    //}
                }
                ThreadAction::CmdPullerPatrol => {
                    //info!("puller_patrol '{}'...", msg.object);
                    if ctx.fcc.after_treament == config::AR_DELETE_FILE_AND_DIRECTORY {
                        puller_patrol_routine(&ctx.fcc.local_root_path, 0, true)?;
                    }
                    report_ready = true;
                }
                ThreadAction::CmdPusherRun => {
                    info!("pusher_run '{}'...", msg.object);
                    ftp.put_file(msg.object.as_str())?;
                    match ctx.fcc.after_treament {
                        config::AR_DELETE_FILE | config::AR_DELETE_FILE_AND_DIRECTORY => {
                            ftp.rm_local_file(msg.object.as_str())
                                .unwrap_or_else(|e| {
                                    audit::audit_alert(
                                        audit::ALERT_TYPE_FILE,
                                        ctx.fcc.channel as u8,
                                        ctx.fcc.vchannel,
                                        audit::AS_TX,
                                        audit::AE_AFTER_TREAMENT,
                                        format!("删除文件'{}'失败", msg.object),
                                    );
                                    error!("删除'{}'失败:'{:?}',继续进行", msg.object, e);
                                })
                        }
                        config::AR_MOVE | config::AR_KEEP => {
                            util::backup_file(&ctx.fcc.local_root_path, &msg.object, ".sent")
                                .unwrap_or_else(|e| {
                                    audit::audit_alert(
                                        audit::ALERT_TYPE_FILE,
                                        ctx.fcc.channel as u8,
                                        ctx.fcc.vchannel,
                                        audit::AS_TX,
                                        audit::AE_AFTER_TREAMENT,
                                        format!("备份文件'{}'失败", msg.object),
                                    );
                                    error!("备份'{}'失败:'{:?}',继续进行", msg.object, e);
                                })
                        }
                        _ => {}
                    }
                }
                ThreadAction::CmdPusherPatrol => {
                    //info!("pusher_patrol '{}'...", msg.object);
                    if ftp.noop()? {
                        let truncate_empty_directory = ctx.fcc.after_treament == config::AR_DELETE_FILE_AND_DIRECTORY;
                        pusher_patrol_routine(&ctx.fcc.local_root_path, 0, truncate_empty_directory)?;
                    }
                    report_ready = true;
                },
                _ => {
                    error!("ftp_thread_handler() unsupported request'{:?}'", msg); //todo
                }
            }
            Ok(())
        };

        if let Err(e) = do_job(&ctx) {
            ctx.pending_job = Some(msg);
            return Err(e);
        } else {
            ctx.fails = 0; //能正常处理任务,进入正循环,清空以往失败次数(如果有的话)
        }
    } //loop

    Ok(())
}

fn puller_patrol_routine(abs_path: &str, depth: u32, truncate_empty_directory: bool) -> Result<()> {
    /*
    if depth == 0 {
        info!("puller_patrol_routine() entry");
    }
    */

    let path = Path::new(abs_path);
    if !path.exists() || !path.is_dir() {
        return Ok(());
    }

    let mut is_empty = true;
    let now = SystemTime::now();
    for entry in path.read_dir()? { 
        is_empty = false;
        if let Ok(entry) = entry {
            let file_name = match entry.file_name().to_str() {
                Some(val) => val.to_string(),
                None => continue,
            };
            if file_name.starts_with(".sent") {
                continue
            }
            if entry.file_type()?.is_dir() {
                let next_abs_path = format!("{}/{}", abs_path, file_name);
                puller_patrol_routine(&next_abs_path, depth+1, truncate_empty_directory)?;
            }
        }
    }

    if depth > 0 && truncate_empty_directory && is_empty {
        let duration_since_mtime = now
            .duration_since(path.metadata()?.modified()?)
            .map_err(|_|"duration_since(mtime) failed")?;
        if duration_since_mtime.as_secs() > 60 {
            //todo:: should we wait 1 minutes before removing this empty directory?
            std::fs::remove_dir(path)
                .map(|_| info!("remove empty directory '{}' ok", abs_path))
                .unwrap_or_else(|e| error!("remove empty directory '{}' failed:{:?}", abs_path, e));
        }
    }

    Ok(())
}

fn pusher_patrol_routine(abs_path: &str, depth: u32, truncate_empty_directory: bool) -> Result<()> {
    /*
    if depth == 0 {
        info!("pusher_patrol_routine() entry");
    }
    */

    let path = Path::new(abs_path);
    if !path.exists() || !path.is_dir() {
        return Ok(());
    }

    let mut is_empty = true;
    let now = SystemTime::now();

    //遍历目录,对于各种原因遗留下来的文件通过重命名触发传输
    for entry in path.read_dir()? { 
        is_empty = false;
        if let Ok(entry) = entry {
            if let Ok(file_type) = entry.file_type() {

                let file_name = match entry.file_name().to_str() {
                    Some(val) => val.to_string(),
                    None => continue,
                };

                if file_name.starts_with(".sent") {
                    continue
                }

                if file_type.is_dir() {
                    let next_abs_path = format!("{}/{}", abs_path, file_name);
                    pusher_patrol_routine(&next_abs_path, depth+1, truncate_empty_directory)?;
                }
                else if file_type.is_file() {
                    if file_name.ends_with(".uploading") || file_name.ends_with(".fail_and_retry") {
                        continue;
                    }

                    if let Ok(meta) = entry.metadata() {
                        if let Ok(mtime) = meta.modified() {
                            if let Ok(duration) = now.duration_since(mtime) {
                                if duration.as_secs() >= 5 {
                                    let src = format!("{}/{}", abs_path, file_name);
                                    let dst = format!("{}/{}.fail_and_retry", abs_path, file_name);
                                    if let Err(e) = std::fs::rename(&src, &dst) {
                                        error!("rename '{}' to '{}' error:{:?}", src, dst, e);
                                        continue;
                                    }
                                    match std::fs::rename(&dst, &src) {
                                        Ok(_) => info!("trigger '{}' ok", &src),
                                        Err(e) => error!("rename '{}' to '{}' error:{:?}", dst, src, e),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    //如果是空目录,且有清理指令(truncate_empty_directory),则清理之
    if depth > 0 && truncate_empty_directory && is_empty {
        let duration_since_mtime = now
            .duration_since(path.metadata()?.modified()?)
            .map_err(|_|"duration_since(mtime) failed")?;
        if duration_since_mtime.as_secs() > 60 {
            //todo:: should we wait 1 minutes before removing this empty directory?
            std::fs::remove_dir(path)
                .map(|_| info!("remove empty directory '{}' successfully", abs_path))
                .unwrap_or_else(|e| error!("remove empty directory '{}' failed:{:?}", abs_path, e));
        }
    }

    Ok(())
}

#[derive(Debug)]
pub struct FtpWorker {
    pub id: usize,
    pub kind: usize,
    pub channel: usize,
    pub stream: Option<UnixStream>,
    pub handle: Option<thread::JoinHandle<()>>,
    pub is_idle: bool,
    pub has_exit: bool,
    pub index: usize,
}

impl FtpWorker {
    pub fn send(&mut self, action: ThreadAction, obj: &str) -> Result<()> {
        let stream = self.stream.as_mut().ok_or("stream is None")?;
        let msg = ThreadMsg {
            channel: self.channel,
            kind: self.kind,
            id: self.id,
            action: action,
            object: obj.to_string(),
        };
        bincode::serialize_into(stream, &msg).chain_err(|| "发送序列化对象失败")?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<ThreadMsg> {
        let stream = self.stream.as_mut().ok_or("stream is None")?;
        Ok(bincode::deserialize_from(stream).chain_err(|| "接收序列化对象失败")?)
    }
}

#[derive(Debug)]
pub struct FtpWorkQueue {
    pub channel: usize,
    pub workers: Vec<FtpWorker>,
    pub q_files: VecDeque<(ThreadAction,String)>,   //Queue of files to be processed
    pub q_idle_workers: VecDeque<usize>,            //Queue of idle workers
}

impl FtpWorkQueue {
    pub fn new(channel: usize) -> FtpWorkQueue {
        let wq = FtpWorkQueue {
            channel: channel,
            workers: Vec::new(),
            q_files: VecDeque::new(),
            q_idle_workers: VecDeque::new(),
        };
        wq
    }

    pub fn is_empty(&self) -> bool {
        return self.workers.len() == 0;
    }

    pub fn is_idle(&self, extra_count: usize) -> bool {
        return self.q_idle_workers.len() + extra_count == self.workers.len()
            && self.q_files.len() == 0;
    }

    pub fn spawn_a_worker(
        &mut self,
        pp: &'static util::ProgParam,
        prog_name: &'static str,
        kind: usize,
        config: &TxConfig,
    ) -> Result<()> {
        let channel = self.channel;
        let index = self.workers.len();
        let id = context::calc_thread_id(channel, kind, index);
        let gc = config.gc.clone();
        let fcc = config
            .get_fcc(channel)
            .ok_or(format!("get_fcc({}) failed", channel))?
            .clone();

        let builder = thread::Builder::new();
        let handle = builder
            .name(format!(
                "{}-{}-{}",
                context::KIND_NAMES[kind],
                channel,
                index
            ))
            .spawn(move || {
                if let Err(e) = thread_run(pp, prog_name, gc, fcc, kind, id, channel) {
                    log_error(&e);
                }
            })?;

        let worker = FtpWorker {
            id: id,
            kind: kind,
            channel: self.channel,
            stream: None,
            handle: Some(handle),
            is_idle: false,
            has_exit: false,
            index: index,
        };

        self.workers.push(worker);
        Ok(())
    }

    pub fn join_a_worker(&mut self, id: usize) {
        let worker = self.get_worker(id);
        let channel = worker.channel;
        let id = worker.id;
        if let Some(handle) = worker.handle.take() {
            let _ = handle
                .join()
                .map(|_| info!("channel {} thread {} joined ok", channel, id))
                .map_err(|e| error!("channel {} joining thread {} failed:{:?}", channel, id, e));
        }
    }

    pub fn stop_workers(&mut self) -> Result<()> {
        info!("ftp_work_queue {} stop_workers()...", self.channel);
        for worker in &mut self.workers {
            //worker.send("THREAD_QUIT", "")?;
            worker.send(ThreadAction::CmdQuit, "")?;
        }
        while self.workers.len() > 0 {
            if let Some(mut worker) = self.workers.pop() {
                worker.handle = None; //implicity detach the thread todo::join or not?
            }
        }
        Ok(())
    }

    pub fn get_worker(&mut self, id: usize) -> &mut FtpWorker {
        let index = id % 100;
        assert!(index < self.workers.len());
        let worker = &mut self.workers[index];
        assert!(worker.id == id);
        worker
    }

    pub fn comes_a_file(&mut self, action: ThreadAction, file: String) -> Result<()> {
        if let Some(idle_id) = self.q_idle_workers.pop_front() {
            let worker = self.get_worker(idle_id);
            worker.send(action, &file)?;
        } else {
            self.q_files.push_back((action,file));
        }
        Ok(())
    }

    pub fn comes_a_worker(&mut self, id: usize) -> Result<()> {
        if let Some((action,file)) = self.q_files.pop_front() {
            let worker = self.get_worker(id);
            worker.send(action, &file)?;
        } else {
            self.get_worker(id).is_idle = true;
            self.q_idle_workers.push_back(id);
        }
        Ok(())
    }

    pub fn accept_worker_stream(&mut self, id: usize, stream: UnixStream) -> Result<()> {
        self.get_worker(id).stream = Some(stream);
        Ok(())
    }
}

