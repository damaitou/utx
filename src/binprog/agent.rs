
use log::{debug, error, info, warn};
use mio::net::{/*TcpStream,*/ TcpListener};
use mio::unix::EventedFd;
use mio::*;

use std::fs::File;
use std::net::{SocketAddr,TcpStream,/*TcpListener, UdpSocket*/};
//use std::time::{Duration, Instant};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, IntoRawFd, FromRawFd};
//use std::os::raw::c_int;
use std::thread;
use std::path::Path;
use docopt::Docopt;
use serde::Deserialize;

use mylib::errors::*;
use mylib::util;

mod watch;
mod agent_def;
use crate::watch::FileChannelWatcher;
use crate::agent_def::*;

const USAGE: &'static str = "
Usage:
    agent -r PATH -w PATH -p PORT [options]
    agent (-h | --help)

Options:
    -r, --readdir PATH      监控PATH目录中新出现的文件并发送该文件
    -w, --writedir PATH     接收文件并保存到PATH目录中
    -p, --port PORT         使用PORT端口与对端进行文件传输
    -c, --cleanup           可选参数,如果指定-c则文件发送完成后删除,否则不删除
    -h, --help              显示本帮助信息
";
const TOKEN_LISTENER: Token = Token(10_000);
const TOKEN_WATCHER: Token = Token(10_001);

const MAX_FILE_ID: FileId = 256;

#[derive(Debug, Deserialize)]
struct Args {
    flag_readdir: String,
    flag_writedir: String,
    flag_port: u16,
    flag_cleanup: bool,
}

impl Args {
    fn check_args(&self) -> Result<()> {
        if !Path::new(&self.flag_readdir).exists() { 
            return Err(format!("'{}'不存在或者无法访问",self.flag_readdir).into()); 
        }
        if !Path::new(&self.flag_writedir).exists() {
            return Err(format!("'{}'不存在或者无法访问",self.flag_writedir).into()); 
        }
        Ok(())
    }
}

//#[derive(Clone)]
struct PushingFile {
    //static information
    f: File,
    last_seq: Sequence,
    file_id: FileId,
    file_size: usize,
    local_file: String,
    local_file_pushing: String,
    //dynamic information
    has_read_bytes: usize,
}

impl PushingFile {
    fn new(write_dir: &String, data_buf: &DataBuf) -> Result<PushingFile> {
        let file_name = data_buf.file_info().get_file_name();
        let local_file = format!("{}/{}", write_dir, file_name);
        let local_file_pushing = format!("{}/{}.pushing", write_dir, file_name);
        let f = util::ensure_file(&local_file_pushing, None).map_err(|e|{
            error!("create local file '{}', error:{:?}", local_file_pushing, e); e
        })?;

        let pf = PushingFile {
            f: f,
            last_seq: data_buf.header.seq,
            file_id: data_buf.header.file_id,
            file_size: data_buf.file_info().file_size,
            local_file: local_file,
            local_file_pushing: local_file_pushing,
            has_read_bytes: 0,
        };
        Ok(pf)
    }

    fn on_file_data(&mut self, data_buf: &DataBuf) -> Result<()> {
        let header_len = std::mem::size_of::<Header>();
        let len = data_buf.header.total_len - header_len;
        let data = &data_buf.data;

        self.last_seq = self.last_seq.wrapping_add(1);
        if self.last_seq != data_buf.header.seq {
            error!("data sequence jump from {} to {}", self.last_seq.wrapping_sub(1), data_buf.header.seq);
            eprintln!("data sequence jump from {} to {}", self.last_seq.wrapping_sub(1), data_buf.header.seq);
            return Err("data sequence out of order".into());
        }

        self.f.write_all(&data[..len])?;
        self.has_read_bytes += len;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        if self.has_read_bytes == self.file_size {
            let msg = format!("file '{}' recv ok, size={}", self.local_file, self.file_size);
            info!("{}", msg);
            println!("{}", msg);
            self.finish_ok()
        } else {
            let msg = format!("文件'{}'大小为{}字节,但只收到{}字节,传输失败", self.local_file, self.file_size, self.has_read_bytes);
            error!("{}",&msg);
            eprintln!("{}",&msg);
            self.finish_err()
        }
    }

    fn finish_err(&mut self) -> Result<()> {
        std::fs::remove_file(&self.local_file_pushing)?;
        Ok(())
    }

    fn finish_ok(&mut self) -> Result<()> {
        std::fs::rename(&self.local_file_pushing, &self.local_file)?;
        Ok(())
    }

}

struct PushingFilesVec {
    pushing_files: Vec<Option<PushingFile>>,
}
impl PushingFilesVec {
    fn new() -> PushingFilesVec {
        let mut pfv = PushingFilesVec {
            pushing_files: Vec::new(),
        };
        for _i in 0..MAX_FILE_ID {
            pfv.pushing_files.push(None);
        }
        pfv
    }

    fn place_pushing_file(&mut self, pf: PushingFile) -> Result<()> {
        let pos = pf.file_id as usize;
        if let Some(old_pf) = self.pushing_files[pos].as_mut() {
            let _ = old_pf.finish(); //ok or not, old_pf must be replaced
        }
        self.pushing_files[pos] = Some(pf);
        Ok(())
    }

    fn remove_pushing_file(&mut self, pos: usize) {
        self.pushing_files[pos] = None;
    }

    fn get_pushing_file(&mut self, pos: usize) -> Option<&mut PushingFile> {
        self.pushing_files[pos].as_mut()
    }
}

struct ReaderRuntime {
    write_dir: String,
    tcp_reader: TcpStream,
    data_buf: DataBuf,
    pfv: PushingFilesVec,
}

impl ReaderRuntime {
    fn new(write_dir: String, tcp_stream: TcpStream) -> ReaderRuntime {
        ReaderRuntime {
            write_dir: write_dir,
            tcp_reader: tcp_stream,
            data_buf: DataBuf::new(), //todo
            pfv: PushingFilesVec::new(),
        }
    }

    fn loop_on_read(&mut self) -> Result<()> {
        loop {
            if let Err(e) = self.data_buf.read_from(&mut self.tcp_reader) {
                eprintln!("loop_on_read() read packet error:{:?}, drop the connection", e);
                error!("loop_on_read() read packet error:{:?}, drop the connection", e);
                return Err(e)?;
            }

            let header_type = self.data_buf.header.header_type;
//println!("loop_on_read, got a data_buf, header_type={}", header_type);
            match header_type {
                AGENT_COMES_A_FILE_INFO => {
println!("loo_on_read, comes_a_file='{}'", self.data_buf.file_info().get_file_name());
                    info!("loo_on_read, comes_a_file={}", self.data_buf.file_info().get_file_name());
                    let mut pf = PushingFile::new(&self.write_dir, &self.data_buf)?;
                    if pf.file_size != 0 {
                        self.pfv.place_pushing_file(pf)?;
                    } else {
                        pf.finish()?;
                    }
                },
                AGENT_COMES_A_FILE_DATA | AGENT_COMES_A_FILE_END => {
                    let file_id = self.data_buf.header.file_id;
                    match self.pfv.get_pushing_file(file_id as usize) {
                        Some(pf) => {
                            let is_err = pf.on_file_data(&self.data_buf).is_err();
                            if is_err || header_type == AGENT_COMES_A_FILE_END {
                                pf.finish()?;
                                self.pfv.remove_pushing_file(file_id as usize);
                            }
                        }
                        None => {
                            eprintln!("loop_on_read() recv packet which has no file-header, drop it");
                            error!("loop_on_read() recv packet which has no file-header, drop it");
                        }
                    }
                },
                _ => {
                    eprintln!("loop_on_read() recv packet with unknow header_type({}), drop it", header_type);
                    warn!("loop_on_read() recv packet with unknow header_type({}), drop it", header_type);
                }
            }
        }
    }
}

struct Runtime {
    args: Args,
    poll: mio::Poll,
    listener: TcpListener,
    watcher: FileChannelWatcher,
    //for write operation
    tcp_writer: Option<TcpStream>,
    tcp_writer_errs: usize,
    //internal states for Writer
    data_buf: DataBuf,
    file_id_seq: FileId,
}

impl Runtime {

    fn send_file_info(&mut self, file_name:&String, file_size: usize) -> Result<FileId> { //return file_id
        self.data_buf.file_info().set_file_name(file_name);
        self.data_buf.file_info().file_size = file_size;

        self.file_id_seq = (self.file_id_seq + 1) % MAX_FILE_ID;
        self.data_buf.header.header_type = AGENT_COMES_A_FILE_INFO;
        self.data_buf.header.file_id = self.file_id_seq;
        self.data_buf.header.total_len = std::mem::size_of::<Header>() + std::mem::size_of::<FileInfo>();

        self.data_buf.header.seq = 0;
        self.data_buf
            .write_to(self.tcp_writer.as_mut().unwrap())
            .map_err(|e|{ self.tcp_writer_errs +=1; e})?; //todo
//println!("sent file_info, file_name={}, total_len={}", file_name, self.data_buf.header.total_len);
        Ok(self.file_id_seq)
    }

    fn send_file_content(&mut self, file_id: FileId, file: &mut File, fsize: usize) -> Result<()> {
        if fsize == 0 {
            return Ok(());
        }
        self.data_buf.header.file_id = file_id;
        self.data_buf.header.seq = 0;
        let mut to_read = fsize;
        loop {
            let nread = file.read(&mut self.data_buf.data)?;
            /*
            if nread == 0 {
                return Ok(());
            }
            */

            to_read -= nread;
            if to_read == 0 {
                self.data_buf.header.header_type = AGENT_COMES_A_FILE_END;
            } else {
                self.data_buf.header.header_type = AGENT_COMES_A_FILE_DATA;
            }

            self.data_buf.header.total_len = std::mem::size_of::<Header>() + nread;
            self.data_buf.header.seq = self.data_buf.header.seq.wrapping_add(1);
            self.data_buf
                .write_to(self.tcp_writer.as_mut().unwrap())
                .map_err(|e|{ self.tcp_writer_errs +=1; e})?; //todo
//println!("sent file_content, file_id={}, total_len={}",  file_id, self.data_buf.header.total_len);
            if to_read == 0 {
                return Ok(())
            }
        }
    }

    fn send_file(&mut self, file_name: &String) -> Result<()> {
        let path = format!("{}/{}", self.args.flag_readdir, file_name);
        let mut f = std::fs::File::open(&path).chain_err(||format!("open('{}') failed", &path))?;
        let fsize = f.metadata().chain_err(||"acquire file metadata failed")?.len();

        let file_id = self.send_file_info(file_name, fsize as usize)?;
        self.send_file_content(file_id, &mut f, fsize as usize)?;

        println!("file '{}' sent ok, size={}", file_name, fsize);
        info!("file '{}' sent ok, size={}", file_name, fsize);

        if self.args.flag_cleanup {
            drop(f);
            let _ = std::fs::remove_file(&path).map_err(|e|error!("delete '{}' error:{:?}", file_name, e));
        }

        Ok(())
    }

    fn process_tcp_stream(&mut self, mut tcp_stream: TcpStream) -> Result<()> {
        self.data_buf
            .read_from(&mut tcp_stream)
            .map_err(|e|format!("read first packet on newly accepted tcp_stream error:{:?}", e))?;
        match self.data_buf.header.header_type {
            PLEASE_READ => {
println!("recv please_read");
                let mut reader_rt = ReaderRuntime::new(self.args.flag_writedir.clone(), tcp_stream);
                let _ = thread::spawn(move || { 
                    let _ = reader_rt
                        .loop_on_read()
                        .map_err(|e|info!("loop_on_read() finished, error={:?}",e)); //todo
                });
            },
            PLEASE_WRITE =>  {
println!("recv please_write");
                if self.tcp_writer.is_none() || self.tcp_writer_errs > 0 {
                    self.tcp_writer = Some(tcp_stream); //新建或者切换tcp_writer
                }
            },
            _ => {
                warn!("unknow header_type {}", self.data_buf.header.header_type);
            }
        }
        Ok(())
    }

    fn on_listener(&mut self) -> Result<()> {
        let (tcp_stream, _peer) = self.listener.accept().chain_err(||"accept failed")?;
println!("accept tcp_stream from {:?}", _peer);
        let tcp_stream = unsafe {std::net::TcpStream::from_raw_fd(tcp_stream.into_raw_fd())};
        tcp_stream.set_nonblocking(false)?;
        self.process_tcp_stream(tcp_stream)
    }

    fn on_watcher(&mut self) -> Result<()> {
        let mut buffer = [0u8; 4096];
        let events = self.watcher
            .notify
            .read_events(&mut buffer)
            .chain_err(||"read inotify events failed")?;
        for event in events {
            let event_name = match event.name {
                Some(val) => val,
                None => continue,
            };
            debug!("file {:?} detected", event_name);
            let file = match event_name.to_str() {
                Some(name) => name.to_string(),
                None => { 
                    error!( "'{:?}' is not a valid unicode file name, skipped", event_name);
                    continue;
                }
            };

            if let Some(detected_file) = self.watcher.is_file_detected(event.wd, &event.mask, &file) {
                if self.tcp_writer.is_some() {
                    info!("sending '{}'...", detected_file);
                    println!("sending '{}'...", detected_file);
                    self.send_file(&detected_file)
                        .map_err(|e|{
                            error!("error sending file '{}':{:?}", detected_file, e); e
                            //todo:: what about the tcp_writer?
                        })?;
                    self.tcp_writer_errs = 0; //文件能传输,说明没问题
                } else {
                    warn!("file '{}' detected, but no data-link established, abort", detected_file);
                    eprintln!("file '{}' detected, but no data-link established, abort", detected_file);
                }
            }
        }
        Ok(())
    }
}

fn run() -> Result<()> {
    let args: Args = Docopt::new(USAGE)
            .and_then(|d| Ok(d.help(true)))
            .and_then(|d| d.deserialize())
            .unwrap_or_else(|e| e.exit());
    println!("args={:?}", args);
    args.check_args()
        .map_err(|e|{
            eprintln!("参数错误:{}",e.description());
            std::process::exit(-1);
        });

    let addr: SocketAddr = format!("[::]:{}",args.flag_port).parse().chain_err(||"invalid address")?;
    let watcher = FileChannelWatcher::new(/*fcc.channel*/0, &args.flag_readdir, 10_001)?;
    let mut rt = Runtime {
        args: args,
        poll: Poll::new().chain_err(||"failed to created Poll instance")?,
        listener: TcpListener::bind(&addr).chain_err(||"绑定地址失败")?,
        watcher: watcher,
        data_buf: DataBuf::new(),
        file_id_seq: 0,
        tcp_writer: None,
        tcp_writer_errs: 0,
    };

    rt.poll
        .register(&rt.listener, TOKEN_LISTENER, Ready::readable(), PollOpt::level())
        .chain_err(|| "register listener failed")?;

    let raw_fd = &rt.watcher.notify.as_raw_fd();
    rt.poll
        .register(&EventedFd(raw_fd), TOKEN_WATCHER, Ready::readable(), PollOpt::level(),)
        .chain_err(|| "register file inotify watcher failed")?;

    let mut events = Events::with_capacity(1024);
    loop {
        rt.poll.poll(&mut events, None).chain_err(|| "Poll失败")?;
        for event in events.iter() {
            match event.token() {
                TOKEN_LISTENER => {
                    let _ = rt.on_listener().map_err(|e|error!("on_listener() error:{:?}",e));
                }
                TOKEN_WATCHER => {
                    let _ = rt.on_watcher().map_err(|e|error!("on_watcher() error:{:?}",e));
                }
                _ => {
                    error!("fatal error: unkown poll event!");
                    eprintln!("fatal error: unkown poll event!");
                    unreachable!();
                }
            }
        }
    }
    //Ok(())
}

fn main()
{
    if let Err(e) = run() {
        eprintln!("fatal error:{:?}", e);
        error!("fatal error:{:?}, process terminated", e);
        util::log_error(&e);
        std::process::exit(-1);
    }
}

