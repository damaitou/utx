extern crate bincode;
extern crate serde;

use log::{debug, error, info, warn};
use std::collections::VecDeque;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use mylib::audit;
use mylib::config::{self, TxConfig};
use mylib::context::{self, ThreadAction, ThreadMsg, KIND_UTX};
use mylib::errors::*;
use mylib::util::{self, log_error};
use mylib::utx;
use mylib::virus;

pub struct UtxThreadContext {
    _pp: &'static util::ProgParam,
    _gc: config::GeneralConfig,
    fcc: config::TxFileChannelConfig,
    pi: config::PhysicalInterface,
    pub scanner: Option<virus::VirusScanner>,
    pub lh: String, //log informaton header
    pub kind: usize,
    pub id: usize,
    stream: UnixStream,
    //for error recovery
    fails: usize,
}

impl UtxThreadContext {
    //fn send(&self, action: &str, obj: &str) -> Result<()> {
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
}

fn utx_thread_handler(ctx: &mut UtxThreadContext) -> Result<()> {
    info!("{} created", ctx.lh);
    let ufs = utx::UtxSender::new(ctx.pi.tx_mac.as_str(), ctx.pi.rx_mac.as_str())
        .ok_or(ErrorKind::UnrecoverableError(1, "加载Utx失败".to_string()))?;

    loop {
        debug!("{} declaring available", ctx.lh);
        //ctx.send("THREAD_READY", "")?;
        ctx.send(ThreadAction::ThreadReady, "")?;

        let msg = ctx.recv()?;
        //if msg.action == "THREAD_QUIT" {
        if msg.action == ThreadAction::CmdQuit {
            info!("{} received 'CmdQuit',quit.", ctx.lh);
            break;
        }

        //decode file/peer_ip/user from msg.object
        let vs: Vec<&str> = msg.object.split('\0').collect();
        let file = if vs.len() < 1 {
            continue;
        } else {
            vs[0]
        };
        let peer_ip = if vs.len() < 2 { "" } else { vs[1] };
        let ftp_user = if vs.len() < 3 { "" } else { vs[2] };
        info!("utx_run '{}'...", file);

        let abs_file = format!("{}/{}", ctx.fcc.local_root_path, file);

        if let Some(scanner) = ctx.scanner.as_mut() {
            debug!("{} scanning '{}'...", ctx.lh, file);
            let (result, msg, backup_mark) = match scanner.scan(abs_file.as_str()) {
                Ok((no_virus, msg)) => {
                    debug!("scan '{}', no_virus={}, msg={}", file, no_virus, msg);
                    (no_virus, msg, ".infected")
                }
                Err(e) => {
                    error!("scanning virus failed:{:?}", e);
                    (false, format!("扫描失败:{:?}", e), ".scan_fail")
                }
            };

            if !result {
                //发现病毒,记录审计信息,并隔离病毒文件
                if ctx.fcc.audit {
                    let time = time::get_time();
                    let far = audit::FileAuditRecord {
                        time_sec: time.sec,
                        time_nsec: time.nsec,
                        side: audit::AS_TX,
                        channel: ctx.fcc.channel as u8,
                        vchannel: ctx.fcc.vchannel,
                        event: audit::AE_VIRUS,
                        result: audit::AR_ERROR,
                        result_msg: msg,
                        ip: peer_ip.to_string(),
                        user: ftp_user.to_string(),
                        file: file.to_string(),
                        file_size: 0, //todo
                    };
                    audit::audit_f(&far);
                }
                util::backup_file(&ctx.fcc.local_root_path, file, backup_mark).unwrap_or_else(
                    |e| {
                        warn!("备份'{}'失败:'{:?}',继续进行", abs_file, e);
                    },
                );
                continue;
            }
        }

        debug!("{} sending '{}'...", ctx.lh, file);
        let (ar_result, ar_msg, fsize) =
            match ufs.send_a_file(ctx.fcc.channel, ctx.fcc.local_root_path.as_str(), file) {
                Ok(fsize) => {
                    info!("{}发送utx文件'{}'成功.", ctx.lh, file);
                    (audit::AR_OK, "".to_string(), fsize)
                }
                Err(e) => {
                    error!("{}发送utx文件'{}'失败:{:?}", ctx.lh, file, e);
                    (audit::AR_ERROR, format!("{:?}", e), 0) //todo::about fsize
                }
            };

        match ctx.fcc.after_treament {
            config::AR_DELETE_FILE | config::AR_DELETE_FILE_AND_DIRECTORY => std::fs::remove_file(&abs_file).unwrap_or_else(|e| {
                if ctx.fcc.audit {
                    audit::audit_alert(
                        audit::ALERT_TYPE_FILE,
                        ctx.fcc.channel as u8,
                        ctx.fcc.vchannel,
                        audit::AS_TX,
                        audit::AE_AFTER_TREAMENT,
                        format!("删除文件'{}'失败", file),
                    );
                }
                warn!("删除'{}'失败:'{:?}',继续进行", abs_file, e);
            }),
            config::AR_MOVE => util::backup_file(&ctx.fcc.local_root_path, file, ".sent")
                .unwrap_or_else(|e| {
                    if ctx.fcc.audit {
                        audit::audit_alert(
                            audit::ALERT_TYPE_FILE,
                            ctx.fcc.channel as u8,
                            ctx.fcc.vchannel,
                            audit::AS_TX,
                            audit::AE_AFTER_TREAMENT,
                            format!("备份文件'{}'失败", file),
                        );
                    }
                    warn!("备份'{}'失败:'{:?}',继续进行", abs_file, e);
                }),
            config::AR_KEEP | _ => {}
        }

        if ctx.fcc.audit {
            let time = time::get_time();
            let far = audit::FileAuditRecord {
                time_sec: time.sec,
                time_nsec: time.nsec,
                side: audit::AS_TX,
                channel: ctx.fcc.channel as u8,
                vchannel: ctx.fcc.vchannel,
                event: audit::AE_FERRY,
                result: ar_result,
                result_msg: ar_msg,
                ip: peer_ip.to_string(),
                user: ftp_user.to_string(),
                file: file.to_string(),
                file_size: fsize as i64,
            };
            audit::audit_f(&far);
        }
    }

    Ok(())
}

pub fn utx_run(
    id: usize,
    pp: &'static util::ProgParam,
    prog_name: &'static str,
    gc: config::GeneralConfig,
    fcc: config::TxFileChannelConfig,
    care_about_virus: bool,
) -> Result<()> {
    let stream = util::unix_connect(&pp.utx_root, prog_name)?;
    eprintln!("utx_thread create a stream {:?}", stream);

    let scanner = match care_about_virus && fcc.scan_virus {
        false => None,
        true => Some(virus::VirusScanner::new(&gc.clamd_sock_file)),
    };

    let pi = gc
        .get_physical_interface(fcc.pi_index)
        .ok_or("gc.get_physical_interface() failed")?
        .clone();
    let mut ctx = UtxThreadContext {
        _pp: pp,
        _gc: gc,
        fcc: fcc,
        pi: pi,
        scanner: scanner,
        kind: KIND_UTX,
        id: id,
        lh: format!("utx {}", id),
        stream: stream,
        fails: 0,
    };

    //ctx.send("THREAD_INIT_OK", "")?;
    ctx.send(ThreadAction::ThreadInitOk, "")?;

    loop {
        //check OUT-OF-BAND message
        if util::data_available(ctx.stream.as_raw_fd()) {
            match ctx.recv() {
                Ok(msg) => {
                    info!("{} recv out_of_band msg:{:?}", ctx.lh, msg);
                    //if msg.action == "THREAD_QUIT" {
                    if msg.action == ThreadAction::CmdQuit {
                        info!("{} received 'CmdQuit', quit.", ctx.lh);
                        break;
                    }
                }
                Err(e) => {
                    error!("{} recv out_of_band data error:{:?}", ctx.lh, e);
                }
            }
            warn!("{} encounter unknown situation, thread quitting...", ctx.lh);
            break;
        }

        if let Err(e) = utx_thread_handler(&mut ctx) {
            util::log_error(&e);
            ctx.fails += 1;

            match e.kind() {
                ErrorKind::UnrecoverableError(_, _) => {
                    //if let Err(e) = ctx.send("THREAD_ERROR_AND_EXIT", "") {
                    if let Err(e) = ctx.send(ThreadAction::ThreadErrorAndExit, "") {
                        error!("{} 发送管道消息'THREAD_ERROR_AND_EXIT'错误:{:?}", ctx.lh, e);
                    }
                    break;
                }
                ErrorKind::RecoverableError(_, _) | _ => {
                    error!("{} 10秒后重试...", ctx.lh);
                    thread::sleep(Duration::from_secs(10));
                }
            }
        } else {
            info!("{} terminated normally", ctx.lh);
            break;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct UtxWorker {
    pub id: usize,
    pub kind: usize,
    pub channel: usize,
    pub stream: Option<UnixStream>,
    pub handle: Option<thread::JoinHandle<()>>,
    pub is_idle: bool,
    pub has_exit: bool,
    pub index: usize,
}

impl UtxWorker {
    //pub fn send(&mut self, action: &str, obj: &str) -> Result<()> {
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
pub struct UtxWorkQueue {
    pub channel: usize,
    pub workers: Vec<UtxWorker>,
    q_files: VecDeque<(ThreadAction,String)>,       //Queue of files to be processed
    q_idle_workers: VecDeque<usize>, //Queue of idle workers
    running: bool,
}

impl UtxWorkQueue {
    pub fn new(channel: usize, running: bool) -> UtxWorkQueue {
        let wq = UtxWorkQueue {
            channel: channel,
            workers: Vec::new(),
            q_files: VecDeque::new(),
            q_idle_workers: VecDeque::new(),
            running: running,
        };
        wq
    }

    pub fn _is_empty(&self) -> bool {
        return self.workers.len() == 0;
    }

    pub fn is_idle(&self) -> bool {
        return self.q_idle_workers.len() == self.workers.len() && self.q_files.len() == 0;
    }

    pub fn spawn_a_worker(
        &mut self,
        pp: &'static util::ProgParam,
        prog_name: &'static str,
        kind: usize,
        config: &TxConfig,
        care_about_virus: bool,
    ) -> Result<()> {
        let index = self.workers.len();
        let channel = self.channel;
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
                if let Err(e) = utx_run(id, pp, prog_name, gc, fcc, care_about_virus) {
                    log_error(&e);
                }
            })?;

        let worker = UtxWorker {
            id: id,
            kind: kind,
            channel: channel,
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
        info!("utx thread stop_workers()...");
        for worker in &mut self.workers {
            //worker.send("THREAD_QUIT", "")?;
            worker.send(ThreadAction::CmdQuit, "")?;
        }
        while self.workers.len() > 0 {
            if let Some(mut worker) = self.workers.pop() {
                worker.handle = None; //implicity detach the thread
            }
        }
        Ok(())
    }

    pub fn get_worker(&mut self, id: usize) -> &mut UtxWorker {
        let index = id % 100;
        assert!(index < self.workers.len());
        let worker = &mut self.workers[index];
        assert!(worker.id == id);
        worker
    }

    pub fn comes_a_file(&mut self, action: ThreadAction, file: String) -> Result<()> {
        if !self.running {
            return Ok(());
        }
        if let Some(idle_id) = self.q_idle_workers.pop_front() {
            let worker = self.get_worker(idle_id);
            //worker.send("UTX_RUN", &file)?;
            worker.send(action, &file)?;
        } else {
            self.q_files.push_back((action,file));
        }
        Ok(())
    }

    pub fn comes_a_worker(&mut self, id: usize) -> Result<()> {
        if let Some((action,file)) = self.q_files.pop_front() {
            let worker = self.get_worker(id);
            //worker.send("UTX_RUN", &file)?;
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
