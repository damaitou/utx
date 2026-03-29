extern crate bincode;
extern crate serde;

use log::{debug, error, info, warn};
use std::collections::VecDeque;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::io::{Read, Write};
use std::net::{TcpStream,};
use std::time::Duration;

use mylib::config::{self, TxConfig, ChannelMode};
use mylib::context::{self, ThreadAction, ThreadMsg, KIND_AGENT};
use mylib::errors::*;
use mylib::util::{self, log_error};
use mylib::utx;
use mylib::virus;

use crate::agent_def::*;

struct AgentWriter {
    channel: usize,
    utx: utx::UtxSender,
}

impl AgentWriter {
    fn new(channel:usize, tx_mac:&str, rx_mac:&str) -> Result<AgentWriter> {
        Ok(AgentWriter {
            channel: channel,
            utx: utx::UtxSender::new(tx_mac, rx_mac)
                .ok_or(ErrorKind::UnrecoverableError(1, "加载Utx失败".to_string()))?
        })
    }
}

impl Write for AgentWriter {
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.utx.send_agent(self.channel, buf)?;
        Ok(buf.len())
    }
}

pub struct AgentThreadContext {
    _pp: &'static util::ProgParam,
    _gc: config::GeneralConfig,
    fcc: config::TxFileChannelConfig,
    _pi: config::PhysicalInterface,
    pub scanner: Option<virus::VirusScanner>,
    pub lh: String, //log informaton header
    pub kind: usize,
    pub id: usize,
    stream: UnixStream,
    pull_stream: Option<TcpStream>,
    utx_writer: AgentWriter,
    //for error recovery
    fails: usize,
}

impl AgentThreadContext {
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

    fn make_pull_connection(&mut self) -> Result<()> {
        if let ChannelMode::ClientPullAgent(cs) = &self.fcc.mode {
            let mut tcp_stream = util::create_bound_tcp_stream(&cs.bind_interface, &cs.remote_ftp_host_address)?;
            let mut header = Header::new();
            header.request_for_write(&mut tcp_stream)?;

            self.pull_stream= Some(tcp_stream);
        } else {
            None.ok_or(ErrorKind::UnrecoverableError(1, "expect 'client_pull_agent' but got something else".to_string()))?;
        }
        Ok(())
    }
}


fn agent_thread_handler(ctx: &mut AgentThreadContext) -> Result<()> {
    info!("{} created", ctx.lh);
    debug!("{} declaring available", ctx.lh);
    ctx.send(ThreadAction::ThreadReady, "")?;

    loop {
        ctx.make_pull_connection().chain_err(||"failed to create agent pull connection")?;

        /*
        let msg = ctx.recv()?;
        if msg.action == ThreadAction::CmdQuit {
            info!("{} received 'CmdQuit',quit.", ctx.lh);
            break;
        }
        */
        let _ = agent_io_copy(ctx.pull_stream.as_mut().unwrap(), &mut ctx.utx_writer)
            .map_err(|e|{
                warn!("{} agent_io_copy() interrupted:{:?}", ctx.lh, e);
            });
        /*
        {
            Ok(amount) => info!("relay {} bytes for channel {}", amount, ctx.fcc.channel),
            Err(e) => {
            },
        }
        */

        thread::sleep(Duration::from_secs(1)); //todo
    }
    //Ok(())
}

pub fn agent_run(
    id: usize,
    pp: &'static util::ProgParam,
    prog_name: &'static str,
    gc: config::GeneralConfig,
    fcc: config::TxFileChannelConfig,
    care_about_virus: bool,
) -> Result<()> {
    let stream = util::unix_connect(&pp.utx_root, prog_name)?;
    eprintln!("agennt_thread create a stream {:?}", stream);

    let scanner = match care_about_virus && fcc.scan_virus {
        false => None,
        true => Some(virus::VirusScanner::new(&gc.clamd_sock_file)),
    };

    let pi = gc
        .get_physical_interface(fcc.pi_index)
        .ok_or("gc.get_physical_interface() failed")?
        .clone();
    let utx_writer = AgentWriter::new(fcc.channel, pi.tx_mac.as_str(), pi.rx_mac.as_str())?;
    let mut ctx = AgentThreadContext {
        _pp: pp,
        _gc: gc,
        fcc: fcc,
        _pi: pi,
        scanner: scanner,
        kind: KIND_AGENT,
        id: id,
        lh: format!("utx {}", id),
        stream: stream,
        pull_stream: None,
        utx_writer: utx_writer,
        fails: 0,
    };

    ctx.send(ThreadAction::ThreadInitOk, "")?;

    loop {
        //check OUT-OF-BAND message
        if util::data_available(ctx.stream.as_raw_fd()) {
            match ctx.recv() {
                Ok(msg) => {
                    info!("{} recv out_of_band msg:{:?}", ctx.lh, msg);
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

        if let Err(e) = agent_thread_handler(&mut ctx) {
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
pub struct AgentWorker {
    pub id: usize,
    pub kind: usize,
    pub channel: usize,
    pub stream: Option<UnixStream>,
    pub handle: Option<thread::JoinHandle<()>>,
    pub is_idle: bool,
    pub has_exit: bool,
    pub index: usize,
}

impl AgentWorker {
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
pub struct AgentWorkQueue {
    pub channel: usize,
    pub workers: Vec<AgentWorker>,
    q_files: VecDeque<(ThreadAction,String)>,       //Queue of files to be processed
    q_idle_workers: VecDeque<usize>, //Queue of idle workers
    running: bool,
}

impl AgentWorkQueue {
    pub fn new(channel: usize, running: bool) -> AgentWorkQueue {
        let wq = AgentWorkQueue {
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
                if let Err(e) = agent_run(id, pp, prog_name, gc, fcc, care_about_virus) {
                    log_error(&e);
                }
            })?;

        let worker = AgentWorker {
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

    pub fn get_worker(&mut self, id: usize) -> &mut AgentWorker {
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

fn agent_io_copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: Read,
    W: Write,
{
    let mut data_buf = DataBuf::new();
    let mut written = 0u64;
    loop {
        data_buf.read_from(reader)?;
        data_buf.write_to(writer)?;
        written += data_buf.header.total_len as u64;
    }
    #[allow(unreachable_code)]
    Ok(written)
}

