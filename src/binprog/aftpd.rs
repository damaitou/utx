
use async_std::net::{TcpListener, TcpStream, UdpSocket, Ipv4Addr, Ipv6Addr, IpAddr, SocketAddr};
use async_std::{io, io::Error, io::ErrorKind, io::Read, io::Write, task, prelude::*};
use async_std::path::Path;
use async_std::fs::File;
use async_std::sync::{Mutex};
use async_std::os::unix::io::{AsRawFd, /*IntoRawFd*/};

use std::os::raw::c_int;
use std::ffi::CString;
use socket2::{Socket, Domain, Type};

use rand::Rng;
use log::{error, warn, info, debug, /*trace*/};
use mylib::config::{TxConfig, TxFileChannelConfig, GeneralConfig, ChannelMode};
use mylib::utx;
use mylib::util;
use mylib::def::MAX_ENCRYPTED_BLOCK_SIZE;

use openssl::symm::{Cipher, encrypt, decrypt};
#[macro_use]
extern crate lazy_static;

extern "C" {
    fn sendfile(out_fd: c_int, in_fd: c_int, offset: *const i64, count: usize) -> isize;
}

lazy_static! {
    static ref CONFIG: Mutex<ConfigWrapper> = Mutex::new(ConfigWrapper { inner: None });
    static ref BREG: Mutex<Breg> = Mutex::new(Breg::new());
}

struct ConfigWrapper {
    inner: Option<TxConfig>,
}
impl ConfigWrapper {
    async fn set_inner(config: TxConfig) {
        CONFIG.lock().await.inner = Some(config);
    }

    async fn get_gc() -> io::Result<GeneralConfig> {
        match CONFIG.lock().await.inner.as_ref() {
            Some(inner) => Ok(inner.gc.clone()),
            None => Err(Error::new(ErrorKind::Other,"ConfigWrapper.inner is null")),
        }
    }

    async fn get_fcc_by_user(user: &String) -> Option<TxFileChannelConfig> {
        if let Some(inner) = CONFIG.lock().await.inner.as_ref() {
            if let Some(fcc) = inner.get_fcc_by_user(user) {
                return Some(fcc.clone());
            }
        }
        None
    }
}

const BREG_STATUS_NONE: u8 = 0;
const BREG_STATUS_PENDING: u8 = 1;
const BREG_STATUS_ESTABLISHED: u8 = 2;
const INVALID_INDEX:usize = 999;

struct Breg {
    breg_status: [u8;256],
    relay_streams: Vec<Option<TcpStream>>,
    channel_to_index: [usize;256],
}
impl Breg {
    fn new() -> Breg {
        let breg = Breg {
            breg_status: [BREG_STATUS_NONE;256],
            relay_streams: Vec::new(),
            channel_to_index: [INVALID_INDEX;256],
        };
        breg
    }

    fn init_breg(&mut self, channel:u8) -> bool {
        match self.breg_status[channel as usize] {
            BREG_STATUS_NONE => {
                self.breg_status[channel as usize] = BREG_STATUS_PENDING;
                true
            }
            _ => false,
        }
    }

    fn get_status(&self, channel:u8) -> u8 {
        self.breg_status[channel as usize]
    }

    fn reset(&mut self, channel:u8) {
        self.breg_status[channel as usize] = BREG_STATUS_NONE;
    }

    fn get_stream(&mut self, channel:u8) -> Option<TcpStream> {
        let index = self.channel_to_index[channel as usize];
        let status = self.breg_status[channel as usize];
        if index == INVALID_INDEX || status != BREG_STATUS_ESTABLISHED {
            return None;
        }
        if index >= self.relay_streams.len() {
            error!("index {} exceed relay_streams.len()={}", index, self.relay_streams.len());
            return None;
        }
        let stream = self.relay_streams[index].take();
        if stream.is_none() {
            self.breg_status[channel as usize] = BREG_STATUS_NONE;
        }
        stream
    }

    fn join_relay_stream(&mut self, channel:u8, stream:TcpStream) {
        let mut index = self.channel_to_index[channel as usize];
        if index == INVALID_INDEX {
            index = self.relay_streams.len();
            self.channel_to_index[channel as usize] = index;
            self.relay_streams.push(Some(stream));
            self.breg_status[channel as usize] = BREG_STATUS_ESTABLISHED;
        } else {
            self.relay_streams[index] = Some(stream);
            self.breg_status[channel as usize] = BREG_STATUS_ESTABLISHED;
        }
    }
}

enum FtpMode {
    Active,
    Passive,
}

enum SessionStatus {
    Ok,
    Err,
    Closed,
    //Stopped,
}

struct FtpSession {
    id: usize,
    gc: GeneralConfig,
    fcc: Option<TxFileChannelConfig>,
    stream: TcpStream,
    ftp_command: String,
    ftp_arg: String,
    ftp_user: String,
    login: bool,
    root_path: String,
    working_path: String,
    buffer: [u8;1024],
    bytes: usize,
    ftp_mode: FtpMode,
    status: SessionStatus,
    rnfr_file: String,
    pasv_listener: Option<TcpListener>,     //for passive mode
    pasv_ipv4_bytes: [u8;4],                //for PASV
    pasv_ipv4_addr: IpAddr,                 //for PASV
    epsv_ipv6_addr: IpAddr,                 //for EPSV
    port_addr: Option<String>,              //for active mode
}

impl FtpSession {
    async fn new(id: usize, stream: TcpStream) -> io::Result<FtpSession> {
        let mut session = FtpSession {
            id: id,
            gc: ConfigWrapper::get_gc().await?,
            fcc: None,
            stream: stream,
            ftp_command: String::new(),
            ftp_arg: String::new(),
            ftp_user: String::new(),
            login: false,
            root_path: String::from("/tmp"),
            working_path: String::from("/"),
            buffer: [0 as u8; 1024],
            bytes: 0,
            ftp_mode: FtpMode::Passive,
            status: SessionStatus::Ok,
            rnfr_file: String::new(),
            pasv_listener: None,
            pasv_ipv4_bytes: [0u8; 4],
            pasv_ipv4_addr: IpAddr::V4(Ipv4Addr::new(127,0,0,1)),
            epsv_ipv6_addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            port_addr: None,
        };
        session.cal_pasv_ip()?;
        Ok(session)
    }

    fn fcc(&self) -> io::Result<&TxFileChannelConfig> {
        match self.fcc.as_ref() {
            Some(fcc) => Ok(fcc),
            None => Err(Error::new(ErrorKind::Other,"fcc is null")),
        }
    }

    fn assemble_realpath(&self, target: &str) -> io::Result<(async_std::path::PathBuf, String)> {
        let dir = match target.len() > 0 && target.chars().nth(0) == Some('/') {
            true => format!("{}{}", &self.root_path, target),
            false => format!("{}{}/{}", &self.root_path, &self.working_path, target),
        };

        let mut ok_pieces: Vec<&str> = Vec::new();
        for piece in dir.split('/') {
            match piece {
                "" | "." => { continue; }
                ".."     => { ok_pieces.pop(); }
                piece    => { ok_pieces.push(piece); }
            }
        }

        let mut path = String::new();
        for s in ok_pieces {
            path.push('/');
            path.push_str(s);
        }

        if !path.starts_with(self.root_path.as_str()) {
            return Err(Error::new(ErrorKind::PermissionDenied, format!("文件路径'{}'非法,超过了允许范围",path)));
        }

        Ok((Path::new(&path).to_path_buf(), path))
    }

    fn socket2_listener(sockaddr: SocketAddr, backlog: i32) -> io::Result<Socket> {
        let domain = match sockaddr.is_ipv4() {
            true => Domain::ipv4(),
            false => Domain::ipv6(),
        };
        let socket = Socket::new(domain, Type::stream(), None)?;
        socket.set_reuse_address(true)?;
        socket.bind(&socket2::SockAddr::from(sockaddr))?;
        socket.listen(backlog)?;
        Ok(socket)
    }

    async fn dynamic_listener(&self, cmd: &str) -> Option<(TcpListener, u16)> {

        let (port_min, port_max) = match self.gc.local_ftp_data_port_range {
            0 => (1024u32, 65536u32),
            range => (
                std::cmp::max(self.gc.local_ftp_data_port_start as u32, 1024u32),
                std::cmp::min(self.gc.local_ftp_data_port_start as u32 + range as u32, 65536u32)),
        };
            
        for _i in 0..10 {
            let port = rand::thread_rng().gen_range(port_min..port_max) as u16;
            let bind_addr = match cmd {
                "PASV" => SocketAddr::new(self.pasv_ipv4_addr, port),
                "EPSV" => match self.epsv_ipv6_addr {
                    IpAddr::V6(_) => SocketAddr::new(self.epsv_ipv6_addr, port),
                    IpAddr::V4(_) => {
                        error!("EPSV not supported for ipv4 connection");
                        return None;
                    },
                },
                _ => unreachable!(),
            };
    
            debug!("trying port '{}'..._i={}", port, _i);
            let listener = match FtpSession::socket2_listener(bind_addr, 1) {
                Ok(l) => TcpListener::from(l.into_tcp_listener()),
                Err(e) => {
                    error!("TcpListener::bind() port '{}' failed:{:?}", port, e);
                    continue;
                }
            };

            return Some((listener, port));
        }
    
        error!("oops!!! failed to create dynamic_listener in 10 tries.");
        None
    }

    async fn do_read<R>(gc: &GeneralConfig, reader: &mut R, buf: &mut [u8], crypto: bool) -> io::Result<(usize, Option<Vec<u8>>)>
    where R: Read + Unpin,
    {
        match crypto {
            false => Ok((reader.read(buf).await?, None)),
            true => {
                let mut n: usize = 0;
                let n_buf = unsafe { std::slice::from_raw_parts_mut(&mut n as *mut _ as *mut u8, 8) };
                match reader.read_exact(n_buf).await {
                    Ok(_) => { if n > MAX_ENCRYPTED_BLOCK_SIZE { 
                        return Err(io::Error::new(io::ErrorKind::Other, "encrypted block too large to read")); 
                    } },
                    Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => return Ok((0, None)),
                    Err(e) => return Err(e),
                }

                let mut encrypted = vec![0u8; n];
                reader.read_exact(&mut encrypted[..n]).await?;

                let decrypted = decrypt(Cipher::aes_128_cbc(), &gc.crypto_key, Some(&gc.crypto_iv), &encrypted[..n])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("decrypt failed:{}", e)))?;
                Ok((decrypted.len(), Some(decrypted)))
            }
        }
    }

    async fn do_write<W>(gc: &GeneralConfig, writer: &mut W, buf: &[u8], crypto: bool) -> io::Result<()> 
    where W: Write + Unpin,
    {
        match crypto {
            false => writer.write_all(buf).await,
            true => {
                let encrypted = encrypt(Cipher::aes_128_cbc(), &gc.crypto_key, Some(&gc.crypto_iv), buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encrypt failed:{}", e)))?;
                let n: usize = encrypted.len();
                if n > MAX_ENCRYPTED_BLOCK_SIZE {
                    return Err(io::Error::new(io::ErrorKind::Other, "encrypted block too large to write"));
                }

                let n_buf  = unsafe { std::slice::from_raw_parts(&n as *const _ as *const u8, 8) };
                writer.write_all(n_buf).await?;
                writer.write_all(&encrypted).await
            }
        }
    }

    async fn do_io_copy<R,W>(
        gc: &GeneralConfig, 
        reader: &mut R, 
        writer: &mut W, 
        read_crypto: bool, 
        write_crypto: bool,
        io_len: u64,
    ) -> io::Result<usize> 
    where 
        R: Read + AsRawFd + Unpin,
        W: Write + AsRawFd + Unpin,
    {
        /*use sendfile() to improve performance if possible*/
        if io_len > 0 && !read_crypto  && !write_crypto {
            let out_fd = writer.as_raw_fd();
            let in_fd = reader.as_raw_fd();
            let mut to_send = io_len as usize;
            //let now = std::time::Instant::now();
            while to_send > 0 {
                match unsafe { sendfile(out_fd, in_fd, std::ptr::null(), to_send) } {
                    -1 => {
                        let e = io::Error::last_os_error();
                        match e.kind() {
                            io::ErrorKind::WouldBlock => {
                                std::thread::sleep(std::time::Duration::from_millis(10)); //sleep 10ms
                            },
                            _ => { return Err(e); }
                        }
                    },
                    sent => { to_send -= sent as usize; }
                }
                //println!("io_len={}, has_sent={}, to_send={}", io_len, io_len as usize -to_send, to_send);
            }
            //println!("elapsed={}", now.elapsed().as_millis());
            return Ok(io_len as usize);
        }

        let mut amount: usize = 0;
        let mut buf = vec![0u8; 64*1024];
        loop {
            let (n, optional_data) = FtpSession::do_read(gc, reader, &mut buf, read_crypto).await?;
            if 0 ==n {
                break;
            }

            let data: &[u8] = match optional_data.as_ref() {
                Some(data) => data,
                None => &buf[..n],
            };

            FtpSession::do_write(gc, writer, data, write_crypto).await?;
            amount += n;
        }
        Ok(amount)
    }

    //return 
    //  Ok(true) if read ok
    //  Ok(false) if ftp client disconnected
    async fn read_ftp_command(&mut self) -> io::Result<bool> {
        loop {
            let (size, optional_data) = FtpSession::do_read(&self.gc, &mut self.stream, &mut self.buffer[self.bytes..], self.gc.crypto).await?;
            if size == 0 {
                self.status = SessionStatus::Closed;
                return Ok(false);
            }
            else if self.bytes+size > self.buffer.len() {
                self.status = SessionStatus::Closed;
                return Err(io::Error::new(ErrorKind::ConnectionAborted, "ftp command too long, abort"));
            }

            if let Some(data) = optional_data {
                self.buffer[self.bytes..self.bytes+size].copy_from_slice(&data);
            }
            
            self.bytes += size;
            if self.bytes < 2
                || self.buffer[self.bytes - 2] != '\r' as u8
                || self.buffer[self.bytes - 1] != '\n' as u8
            {
                continue;
            }

            self.ftp_command.clear();
            self.ftp_arg.clear();

            let mut i = 0;
            while i<self.bytes-2 && self.buffer[i] != b' ' {
                self.ftp_command.push(self.buffer[i] as char);
                i += 1;
            }

            i += 1; //skip the space
            if i<self.bytes-2 {
                self.ftp_arg = String::from_utf8_lossy(&self.buffer[i..(self.bytes - 2)]).to_string();
            }
            
            self.bytes = 0;
            break;
        }
        Ok(true)
    }

    async fn answer(&mut self, resp: &str) -> io::Result<()> {
        FtpSession::do_write(&self.gc, &mut self.stream, resp.as_bytes(), self.gc.crypto).await
            .and_then(|_|{ 
                debug!("ftp session_id {} => '{}'", self.id, resp.trim_end_matches(|c|c=='\r'||c=='\n')); 
                Ok(()) 
            })
            .map_err(|e|{
                self.status = SessionStatus::Err;
                e
            })
    }

    async fn process_ftp_command(&mut self) -> io::Result<()> {
        debug!("ftp session_id {} <= '{}', ftp_arg='{}'", self.id, self.ftp_command, self.ftp_arg);
        if self.login == false
            && self.ftp_command != "USER"
            && self.ftp_command != "PASS"
            && self.ftp_command != "QUIT"
            && self.ftp_command != "PBSZ"
            && self.ftp_command != "PROT"
            && self.ftp_command != "CCC"
            && self.ftp_command != "AUTH"
        {
            return self.answer("530 Please login with USER and PASS.\r\n").await;
        }

        match self.ftp_command.as_str() {
            "USER" =>           self.on_user().await?,
            "PASS" =>           self.on_pass().await?,
            "QUIT" =>           self.on_quit().await?,
            "CWD" =>            self.on_cwd().await?,
            "PWD" =>            self.on_pwd().await?,
            "CDUP" =>           self.on_cdup().await?,
            "MKD" =>            self.on_mkd().await?,
            "DELE" =>           self.on_dele().await?,
            "RMD" =>            self.on_rmd().await?,
            "SIZE" =>           self.on_size().await?,
            "PORT" | "EPRT" =>  self.on_port_eprt().await?,
            "PASV" | "EPSV" =>  self.on_pasv_epsv().await?,
            "LIST" | "NLST" =>  self.on_list_nlst().await?,
            "RNFR" | "RNTO" =>  self.on_rnfr_rnto().await?,
            "RETR" =>           self.on_retr().await?,
            "STOR" =>           self.on_stor().await?,
            "FEAT" =>           self.on_feat().await?,
            "TYPE" =>           self.answer("200 TYPE is now 8-bit binary\r\n").await?, //'TYPE I' or 'TYPE A', we use binary mode 
            "SYST" =>           self.answer("215 UNIX Type: L8\r\n").await?,
            "NOOP" =>           self.answer("200 NOOP okay.\r\n").await?,
            "BREG" =>           self.on_breg().await?,
            "BQRY" =>           self.on_bqry().await?,
            "BJON" =>           self.on_bjon().await?,
            "BSND" =>           self.on_bsnd().await?,
            "BLOC" =>           self.on_bloc().await?,
            "SLOC" =>           self.on_sloc().await?,
            "NATR" =>           self.on_natr().await?,
            _ =>                self.answer("500 unknow command.\r\n").await?,
            /*
            "ABOR" => self.cancel_thread(),
            */
        }
        Ok(())
    }

    async fn on_user(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            self.answer("430 please provide user name\r\n").await
        } else {
            self.ftp_user = self.ftp_arg.clone();
            self.answer("331 User ok, Waiting for the password.\r\n").await
        }
    }

    async fn on_pass(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty()  {
            return self.answer("430 please provide password\r\n").await;
        }

        let fcc = match ConfigWrapper::get_fcc_by_user(&self.ftp_user).await {
            Some(fcc) => fcc,
            None => {
                return self.answer("430 invalid username or password.\r\n").await;
            }
        };

        let ss = match &fcc.mode {
            ChannelMode::Server(ss) => ss,
            _ => {
                return Err(Error::new(ErrorKind::Other, "invalid configuration"));
            }
        };

        let pass = self.ftp_arg.clone();
        match pass == ss.local_ftp_password {
            true => {
                self.root_path = ss.local_root_path.trim_end_matches('/').to_string();
                self.root_path = match self.assemble_realpath("/") {
                    Ok((_, s)) => s,
                    Err(_) => {
                        return self.answer("430 server configuration error(1)\r\n").await;
                    }
                };
                if let Err(e) = async_std::fs::create_dir_all(&self.root_path).await {
                        error!("failed to create_directory '{}', error={:?}", self.root_path, e);
                        return self.answer("430 server configuration error(2)\r\n").await;
                }

                //IP地址过滤
                if let Some(ips) = ss.allow_ips.as_ref() {
                    match self.stream.peer_addr() {
                        Ok(addr) => {
                            if !ips.contains(&addr.ip()) {
                                self.status = SessionStatus::Closed;
                                warn!("{} attempt to login from not-allowed-host {}", self.ftp_user, addr.ip());
                                return self.answer("430 login from your host is not allowed.\r\n").await;
                            }
                        }
                        Err(e) => {
                            warn!("client {} cant acquire peer_address:{:?}", /*self.id*/1, e); //todo
                            return self.answer("430 acquire network address error\r\n").await;
                        }
                    }
                }

                self.fcc = Some(fcc);
                self.login = true;
                self.answer("230 login ok.\r\n").await?;
            }
            false => {
                self.answer("430 invalid username or password.\r\n").await?;
            }
        }
        Ok(())
    }

    async fn on_feat(&mut self) -> io::Result<()> {
        return self.answer("211-Features\r\n EPRT\r\n EPSV\r\n PASV\r\n SIZE\r\n UTF8\r\n211 End\r\n").await
    }

    async fn on_size(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            return self.answer("430 invalid command.\r\n").await;
        }
        match self.assemble_realpath(&self.ftp_arg) {
            Ok((pb, _s)) => {
                match async_std::fs::metadata(pb).await {
                    Ok(meta) => {
                        let resp = format!("213 {}\r\n", meta.len());
                        self.answer(resp.as_str()).await?;
                    }
                    Err(_) => {
                        self.answer("550 please check file existence.\r\n").await?;
                    }
                }
            }
            Err(_) => {
                self.answer("430 invalid filepath.\r\n").await?;
            }
        }
        Ok(())
    }

    async fn on_rmd(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            return self.answer("430 invalid command.\r\n").await;
        }
        match self.assemble_realpath(&self.ftp_arg) {
            Ok((pb, _s)) => {
                if !pb.is_dir().await {
                    return self.answer("550 not a directory.\r\n").await;
                }
                match async_std::fs::remove_dir(pb).await {
                    Ok(_) => {
                        self.answer("250 directory removed.\r\n").await?;
                    }
                    Err(_) => {
                        self.answer("550 failed to remove directory.\r\n").await?;
                    }
                }
            }
            Err(_) => {
                self.answer("430 invalid filepath.\r\n").await?;
            }
        }
        Ok(())
    }

    async fn on_dele(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            return self.answer("430 invalid command.\r\n").await;
        }
        match self.assemble_realpath(&self.ftp_arg) {
            Ok((pb, _s)) => {
                match async_std::fs::remove_file(pb).await {
                    Ok(_) => {
                        self.answer("250 file deleted.\r\n").await?;
                    }
                    Err(_) => {
                        self.answer("550 failed to delete file.\r\n").await?;
                    }
                }
            }
            Err(_) => {
                self.answer("430 invalid filepath.\r\n").await?;
            }
        }
        Ok(())
    }

    async fn on_mkd(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            return self.answer("430 invalid command.\r\n").await;
        }

        let path = self.assemble_realpath(&self.ftp_arg);
        if let Ok((path, s)) = path {
            if !path.exists().await {
                let c_path = CString::new(s)?;
                let ret = unsafe {
                    libc::mkdir(
                        c_path.as_ptr(),
                        libc::S_IRWXU | libc::S_IRWXG | libc::S_IRWXO,
                    ) as i32
                };
                if ret == 0 {
                    self.answer("257 directory created.\r\n").await?;
                } else {
                    self.answer("550 fail to create directory.\r\n").await?;
                }
            } else {
                self.answer("550 file or directory exists.\r\n").await?;
            }
        } else {
            self.answer("550 invalid pathname.\r\n").await?;
        }
        Ok(())
    }

    async fn on_pwd(&mut self) -> io::Result<()> {
        let pwd = format!("257 {} is your current location\r\n", self.working_path);
        self.answer(pwd.as_str()).await
    }

    async fn on_cdup(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            self.ftp_arg = "..".to_string();
        }
        self.on_cwd().await
    }

    async fn on_cwd(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            return self.answer("430 please provide password\r\n").await;
        }
        let mut msg = format!("530 can't change directory to '{}'.\r\n", self.ftp_arg);
        let path = self.assemble_realpath(if self.ftp_arg.is_empty() { "" } else { self.ftp_arg.as_str() });
        if let Ok((path, s1)) = path {
            if path.is_dir().await {
                let to_skip = self.root_path.len();
                let to_take = s1.len() - self.root_path.len();
                self.working_path = s1.chars().skip(to_skip).take(to_take).collect();
                if self.working_path.len() == 0 {
                    self.working_path.push('/');
                }
                msg = format!("250 OK. Current directory is '{}'.\r\n", self.working_path);
            }
        }
        self.answer(msg.as_str()).await
    }

    async fn on_quit(&mut self) -> io::Result<()> {
        self.login = false;
        self.status = SessionStatus::Closed;
        self.answer("221 logout.\r\n").await
    }

    async fn on_port_eprt(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            return self.answer("430 PORT failed: invalid parameter.\r\n").await;
        }

        let content = CString::new(self.ftp_arg.as_bytes())?;

        if self.ftp_command == "PORT" {
            let format = CString::new("%d,%d,%d,%d,%d,%d")?;
            let val = [0 as libc::c_int; 6];
            let n = unsafe {
                libc::sscanf(
                    content.as_ptr(),
                    format.as_ptr(),
                    &(val[0]),
                    &(val[1]),
                    &(val[2]),
                    &(val[3]),
                    &(val[4]),
                    &(val[5]),
                ) as i32
            };
    
            if n < 6 {
                return self.answer("430 PORT failed: invalid parameter.\r\n").await;
            }
            self.port_addr = Some(format!(
                "{}.{}.{}.{}:{}",
                val[0], val[1], val[2], val[3], val[4] * 256 + val[5]
            ));
            self.answer("200 PORT command accepted.\r\n").await?;
        }
        else if self.ftp_command == "EPRT" {
            let vs: Vec<&str> = self.ftp_arg.split('|').collect();
            if  vs.len() != 5 {
                return self.answer("430 EPRT failed: invalid parameter(1).\r\n").await;
            }

            let proto:i32 = match vs[1].parse() {
                Ok(val) => val,
                Err(_) => {
                    return self.answer("430 EPRT failed: invalid parameter(2).\r\n").await;
                }
            };
            let host = vs[2];
            let port:u16 = match vs[3].parse() {
                Ok(val) => val,
                Err(_) => {
                    return self.answer("430 EPRT failed: invalid parameter(3).\r\n").await;
                }
            };

            debug!("EPRT proto={},host={},port={}", proto, host, port);
            self.port_addr = match proto {
                1 => Some(format!("{}:{}", host, port)),
                2 => Some(format!("[{}]:{}", host, port)),
                _ => {
                    return self.answer("430 EPRT failed: invalid parameter(4).\r\n").await;
                }
            };
            self.answer("200 EPRT command accepted.\r\n").await?;
        }

        self.ftp_mode = FtpMode::Active;
        Ok(())
    }

    fn cal_pasv_ip(&mut self) ->io::Result<()> {
        let local_ip = self.stream.local_addr()?.ip();
        let mut ip_v = match local_ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let len = ip_v.len();
        let v = &mut ip_v[len-4..];
        if v[0]==0 && v[1]==0 && v[2]== 0 && v[3]==0 {
            v[0] = 127;
            v[3] = 1;
        }
        self.epsv_ipv6_addr = local_ip;
        self.pasv_ipv4_addr = IpAddr::V4(Ipv4Addr::new(v[0], v[1], v[2], v[3]));
        match self.gc.local_ftp_pasv_ip.as_ref() {
            Some(ip) => self.pasv_ipv4_bytes.copy_from_slice(&ip.octets()),
            None =>     self.pasv_ipv4_bytes.copy_from_slice(v),
        }
        Ok(())
    }

    async fn on_pasv_epsv(&mut self) -> io::Result<()> {
        let (listener, local_port) = match self.dynamic_listener(&self.ftp_command).await { 
            Some((l,p)) => (l,p),
            None => {
                return self.answer("451 failed to enter pasive mode\r\n").await;
            }
        };

        let pasv_resp = match self.ftp_command.as_str() {
            "PASV" => format!(
                "227 entering passive mode ({},{},{},{},{},{})\r\n",
                self.pasv_ipv4_bytes[0],
                self.pasv_ipv4_bytes[1],
                self.pasv_ipv4_bytes[2],
                self.pasv_ipv4_bytes[3],
                local_port / 256,
                local_port % 256
            ),
            "EPSV" => format!("229 entering passive mode (|||{}|)\r\n", local_port),
            _ => unreachable!(),
        };
        self.pasv_listener = Some(listener);
        self.ftp_mode = FtpMode::Passive;
        self.answer(&pasv_resp).await
    }

    async fn accept_data_connection(&mut self) -> io::Result<TcpStream> {
        let listener = match self.pasv_listener.take() {
            Some(val) => val,
            None => {
                self.answer("430 please PASV or PROT first.\r\n").await?;
                return Err(Error::new(ErrorKind::Other,"pasv_listener is none"));
            }
        };
        let (d_stream, _) = match listener.accept().await {
            Ok(val) => val,
            Err(e) => {
                self.answer("430 failed to accept data connection.\r\n").await?;
                return Err(e);
            }
        };

        Ok(d_stream)
    }

    async fn connect_data_connection(&mut self) -> io::Result<TcpStream> {
        let port_addr = match self.port_addr.take() {
            Some(val) => val,
            None => {
                self.answer("430 please PASV or PROT first.\r\n").await?;
                return Err(Error::new(ErrorKind::Other, "port_address is none"));
            }
        };
        let d_stream = match TcpStream::connect(&port_addr).await {
            Ok(val) => val,
            Err(e) => {
                let msg = format!("430 failed to connect to port address {}.\r\n", port_addr);
                self.answer(&msg).await?;
                return Err(e);
            }
        };

        Ok(d_stream)
    }

    async fn prepare_for_data_connection_job(&mut self) -> io::Result<(TcpStream, String)> {
        let command = self.ftp_command.as_str();
        if (command == "RETR" ||
            command == "STOR" ||
            command == "BLOC" ||
            command == "SLOC" ||
            command == "NATR") && self.ftp_arg.is_empty()
        {
            self.pasv_listener = None;
            self.answer("430 invalid command.\r\n").await?;
            return Err(Error::new(ErrorKind::Other, format!("no parameter for command '{}'",self.ftp_command)));
        }

        let pb = self.assemble_realpath(if self.ftp_arg.is_empty() { "" }  else { &self.ftp_arg });
        let path = match pb {
            Ok((_, path)) => path,
            Err(_) => {
                self.pasv_listener = None;
                self.answer("430 invalid parameter.\r\n").await?;
                return Err(Error::new(ErrorKind::Other, format!("invalid parameter '{}'",self.ftp_arg)));
            }
        };

        let d_stream = match self.ftp_mode {
            FtpMode::Active => {
                match self.connect_data_connection().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!("failed to establish data connection actively, error:{:?}", e);
                        return Err(e);
                    }
                }
            }
            FtpMode::Passive => {
                match self.accept_data_connection().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!("failed to establish data connection passively, error:{:?}", e);
                        return Err(e);
                    }
                }
            }
        };

        d_stream.set_nodelay(true)?;

        Ok((d_stream, path))
    }

    async fn on_rnfr_rnto(&mut self) -> io::Result<()> {
        if self.ftp_arg.is_empty() {
            return self.answer("430 invalid command.\r\n").await;
        }

        match self.assemble_realpath(&self.ftp_arg) {
            Ok((pb, s)) => match self.ftp_command.as_str() {
                "RNFR" => match pb.exists().await {
                    true => {
                        self.rnfr_file = s;
                        self.answer("350 RNFR accepted.\r\n").await?;
                    }
                    false => {
                        self.answer("550 file/directory not existed.\r\n").await?;
                    }
                },
                "RNTO" => {
                    if 0 == self.rnfr_file.len() {
                        self.answer("503 please RNFR before RNTO.\r\n").await?;
                        return Ok(());
                    }
                    if pb.exists().await {
                        self.answer("503 RNTO file already exists.\r\n").await?;
                        return Ok(());
                    }
                    match  async_std::fs::rename(&self.rnfr_file, &s).await {
                        Ok(_) => {
                            self.answer("250 rename ok.\r\n").await?;
                        }
                        Err(e) => {
                            self.answer("503 failed to rename.\r\n").await?;
                            error!("RNTO rename file '{}' error:{:?}", self.rnfr_file, e);
                        }
                    }
                    self.rnfr_file.clear();
                }
                _ => {}
            },
            Err(_) => {}
        }
        Ok(())
    }

    async fn on_list_nlst(&mut self) -> io::Result<()> {
        let (mut d_stream, target) = self.prepare_for_data_connection_job().await?;
        let mut breg_pending = false;
        if self.ftp_command == "LIST" {
            let channel = self.fcc()?.channel;
            let breg = BREG.lock().await;
            if breg.get_status(channel as u8) == BREG_STATUS_PENDING {
                breg_pending = true;
            }
        }

        let mut list = String::new();

        let path = Path::new(&target);
        match path.exists().await {
            true => match path.is_dir().await {
                true => {
                    self.answer("150 Here comes the listing.\r\n").await?;
                    let mut entries = match path.read_dir().await {
                        Ok(val) => val,
                        Err(e) => {
                            self.answer("430 failed to list file or directory\r\n").await?;
                            warn!("cmd={},read_dir() failed:{:?}", self.ftp_command, e);
                            return Ok(());
                        }
                    };

                    while let Some(entry) = entries.next().await {
                        if let Ok(entry) = entry {
                            match self.ftp_command.as_str() {
                                "LIST" | "LREG" => {
                                    if let Some(value) = entry.path().to_str() {
                                        util::get_file_info(value, &mut list);
                                    }
                                }
                                "NLST" => {
                                    if let Some(value) = entry.file_name().to_str() {
                                        list.push_str(&format!("{}\r\n", value));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    if breg_pending {
                        list.push_str("yrwxr-xr-x  1  0  0  155  Oct 18 15:03 $B$L$O$C$K$\r\n");
                    }
                    FtpSession::do_write(&self.gc, &mut d_stream, list.as_bytes(), self.gc.crypto).await?;
                    self.answer("226 list ok\r\n").await?;
                } 
                false => {
                    self.answer("150 Here comes the listing.\r\n").await?;
                    util::get_file_info(&target, &mut list);
                    FtpSession::do_write(&self.gc, &mut d_stream, list.as_bytes(), self.gc.crypto).await?;
                    self.answer("226 list ok\r\n").await?;
                }
            },
            false => {
                self.answer("430 no such file or directory.\r\n").await?;
            }
        }
        Ok(())
    }

    async fn on_retr(&mut self) -> io::Result<()> {
        let (mut d_stream, target) = self.prepare_for_data_connection_job().await?;
        match File::open(&target).await {
            Ok(mut f) => {
                let fsize = f.metadata().await?.len();
                self.answer("150 here comes the file\r\n").await?;
                match FtpSession::do_io_copy(&self.gc, &mut f, &mut d_stream, false, self.gc.crypto, fsize).await {
                    Ok(amount) => {
                        let info = format!("226 RETR ok, {} bytes transfered.\r\n", amount);
                        self.answer(&info).await?;
                    }
                    Err(e) => {
                        error!("RETR error:{:?}", e);
                        self.answer("550 RETR failed(1)\r\n").await?;
                    }
                }
            }
            Err(e) => {
                error!("RETR error:{:?}", e);
                self.answer("550 RETR failed(2)\r\n").await?;
            }
        }
        Ok(())
    }

    async fn on_stor(&mut self) -> io::Result<()> {
        let (mut d_stream, target) = self.prepare_for_data_connection_job().await?;
        let local_file = target;
        let local_file_uploading = format!("{}.uploading", local_file);
        match File::create(&local_file_uploading).await {
            Ok(mut f) => {
                self.answer("150 ready to receive data\r\n").await?;
                match FtpSession::do_io_copy(&self.gc, &mut d_stream, &mut f, self.gc.crypto, false, 0).await {
                    Ok(_amt) => {
                        if let Err(e) = async_std::fs::rename(&local_file_uploading, &local_file).await {
                            self.answer("550 file operation eror.\r\n").await?;
                            error!("on_stor() rename file '{}' failed:{:?}", local_file_uploading, e);
                        } else {
                            let info = format!("226 STOR ok, {} bytes received.\r\n", _amt);
                            self.answer(&info).await?;
                        }
                    }
                    Err(e) => {
                        drop(f);
                        let _ = async_std::fs::remove_file(&local_file_uploading).await;
                        self.answer("550 STOR failed(1)\r\n").await?;
                        error!("STOR error:{:?}", e);
                    }
                }
            }
            Err(e) => {
                self.answer("550 STOR failed(2)\r\n").await?;
                error!("STOR error:{:?}", e);
            }
        }
        Ok(())
    }

    async fn on_breg(&mut self) -> io::Result<()> {
        let mut breg = BREG.lock().await;
        let answer: &str;
        match breg.init_breg(self.fcc()?.channel as u8) {
            true => {
                answer = "200 bloc requirement registered ok\r\n";
            }
            false => {
                answer = "125 bloc requirement already registered\r\n";
            }
        }
        drop(breg);
        self.answer(answer).await
    }

    async fn on_bqry(&mut self) -> io::Result<()> {
        let breg = BREG.lock().await;
        let answer: &str;
        match breg.get_status(self.fcc()?.channel as u8) {
            BREG_STATUS_NONE => answer = "421 no bloc requirement registered\r\n",
            BREG_STATUS_PENDING => answer = "350 bloc requirement pending\r\n",
            BREG_STATUS_ESTABLISHED => answer = "200 bloc established\r\n",
            _ => unreachable!(),
        }

        drop(breg);
        self.answer(answer).await
    }

    async fn on_bjon(&mut self) -> io::Result<()> {
        let (d_stream, _target) = self.prepare_for_data_connection_job().await?;
        let channel = self.fcc()?.channel;

        let mut answer: &str = "421 bloc service not available";
        let mut breg = BREG.lock().await;
        let status = breg.get_status(channel as u8);
        match status {
            BREG_STATUS_NONE => {
                answer = "421 no pending bloc requirement\r\n";
            }
            BREG_STATUS_ESTABLISHED => {
                answer = "125 bloc has been occupied\r\n";
            }
            BREG_STATUS_PENDING => {
                breg.join_relay_stream(channel as u8, d_stream);
                answer = "200 bloc joined ok\r\n";
            }
            _ => {}
        }
        
        drop(breg);
        self.answer(answer).await
    }

    async fn on_bsnd(&mut self) -> io::Result<()> {
        let (mut d_stream, _target) = self.prepare_for_data_connection_job().await?;
        let channel = self.fcc()?.channel;

        let mut breg = BREG.lock().await; //critical region starts here
        let mut relay_stream = match breg.get_stream(channel as u8) {
            Some(s) => s,
            None => {
                error!("BSND failed to acquire relay_stream");
                return self.answer("421 unable to acquire peer stream\r\n").await;
            }
        };
        drop(breg); //critical region ends here
        
        let mut buffer = [0 as u8; 4096];
        self.answer("150 ready to receive data\r\n").await?;
        loop {
            match d_stream.read(&mut buffer).await {
                Ok(size) => {
                    if size == 0 {
                        self.answer("226 BSND ok.\r\n").await?;
                        break;
                    }
                    if let Err(e) = relay_stream.write_all(&buffer[..size]).await {
                        error!("realy_stream writing bloc data error:{:?}", e);
                        self.answer("550 peer stream network error\r\n").await?;
                        break;
                    }
                }
                Err(e) => {
                    error!("BSND network error:{:?}", e);
                    self.answer("550 network error.\r\n").await?;
                    break;
                }
            }
        }
        
        let mut breg = BREG.lock().await; 
        breg.reset(channel as u8);  //bloc session over, rest breg to allow another session
        drop(breg);
        Ok(())
    }

    async fn on_bloc(&mut self) -> io::Result<()> {
        let (mut d_stream, target) = self.prepare_for_data_connection_job().await?;
        let channel = self.fcc()?.channel;

        let pi = match self.gc.get_physical_interface(self.fcc()?.pi_index) {
            Some(pi) => pi,
            None => return Err(Error::new(ErrorKind::Other, "get_physical_interface() failed.")),
        };
        let us = match utx::UtxSender::new(&pi.tx_mac, &pi.rx_mac) {
            Some(us) => us,
            None => {
                error!("UtxSender::new() failed.");
                self.answer("553 unable to create file channel.\r\n").await?;
                return Ok(());
            }
        };
        let path = &self.fcc()?.local_root_path;
        let file:String = target.chars().skip(path.len()).take(target.len()-path.len()).collect();
    
        us.send_bloc_header(channel as usize, path, &file);
    
        let mut len: usize;
        let mut buffer = [0 as u8; 1024*64];
        self.answer("150 ready to receive data\r\n").await?;
        loop {
            match d_stream.read_exact(&mut buffer[..5]).await {
                Ok(_) => {
                    let s = match std::str::from_utf8(&buffer[..5]) {
                        Ok(s) => s,
                        Err(e) => {
                            self.answer("550 invalid data(1).\r\n").await?;
                            error!("std::str::from_utf8() error:{:?}", e);
                            return Err(Error::new(ErrorKind::Other,"failed to retrive the first 5 bytes of packet"));
                        }
                    };
                    len = match s.parse() {
                        Ok(len) => len,
                        Err(e) => {
                            self.answer("550 invalid data(2).\r\n").await?;
                            error!("std::str::parse() error:{:?}", e);
                            return Err(Error::new(ErrorKind::Other, "failed to parse() packet length"));
                        },
                    };
                    if len > 1024*64 as usize {
                        self.answer("550 invalid data(3).\r\n").await?;
                        None.ok_or(Error::new(ErrorKind::Other, format!("invalid length {}", len)))?;
                    } 
                }
                Err(e) => {
                    error!("BLOC network error:{:?}", e);
                    self.answer("550 network error.\r\n").await?;
                    break;
                }
            }
            debug!("BLOC data_length={}", len);
            match d_stream.read_exact(&mut buffer[..len]).await {
                Ok(_) => {
                    us.send_bloc_buf(self.fcc()?.channel as usize, &buffer[..len], false, 1); //todo
                }
                Err(e) => {
                    error!("BLOC network error:{:?}", e);
                    self.answer("550 network error.\r\n").await?;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn on_sloc(&mut self) -> io::Result<()> {
        let (mut d_stream, target) = self.prepare_for_data_connection_job().await?;

        let channel = self.fcc()?.channel;
        let pi = match self.gc.get_physical_interface(self.fcc()?.pi_index) {
            Some(pi) => pi,
            None => return Err(Error::new(ErrorKind::Other, "get_physical_interface() failed.")),
        };
        let us = match utx::UtxSender::new(&pi.tx_mac, &pi.rx_mac) {
            Some(us) => us,
            None => {
                error!("SLOC UtxSender::new() failed.");
                return self.answer("553 unable to create file channel.\r\n").await;
            }
        };
        let path = &self.fcc()?.local_root_path;
        let file:String = target.chars().skip(path.len()).take(target.len()-path.len()).collect();
    
        us.send_bloc_header(channel as usize, path, &file);
    
        let mut buffer = [0 as u8; 4096];
        self.answer("150 ready to receive data\r\n").await?;
        loop {
            match d_stream.read(&mut buffer).await {
                Ok(size) => {
                    if size == 0 {
                        self.answer("226 STOR ok.\r\n").await?;
                        break;
                    }
                    us.send_bloc_buf(channel as usize, &buffer[..size], false, 0); //todo
                }
                Err(e) => {
                    error!("SLOC network error:{:?}", e);
                    self.answer("550 network error.\r\n").await?;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn on_natr(&mut self) -> io::Result<()> {
        let (mut d_stream, _target) = self.prepare_for_data_connection_job().await?;

        let ipaddr: IpAddr = match self.fcc()?.relay_ip.parse() {
            Ok(ipaddr) => ipaddr,
            Err(e) => {
                self.answer("550 configuration error (relay_ip).\r\n").await?;
                return Err(Error::new(ErrorKind::Other,format!("relay_ip地址解释失败:{:?}",e)));
            }
        };
        let addr = SocketAddr::new(ipaddr, self.fcc()?.relay_port);
        let socket = match UdpSocket::bind("[::]:0").await {
            Ok(socket) => socket,
            Err(e) => {
                self.answer("550 establish relay channel failed.\r\n").await?;
                return Err(Error::new(ErrorKind::Other, format!("绑定UDP地址失败:{:?}",e)));
            }
        };
    
        let mut len: usize;
        let mut buffer = [0 as u8; 1024*64];
        self.answer("150 ready to receive data\r\n").await?;
        loop {
            match d_stream.read_exact(&mut buffer[..5]).await {
                Ok(_) => {
                    let s = match std::str::from_utf8(&buffer[..5]) {
                        Ok(s) => s,
                        Err(e) => {
                            self.answer("550 invalid data(1).\r\n").await?;
                            error!("std::str::from_utf8() error:{:?}", e);
                            return Err(Error::new(ErrorKind::Other,"failed to retrive the first 5 bytes of packet"));
                        }
                    };
                    len = match s.parse() {
                        Ok(len) => len,
                        Err(e) => {
                            self.answer("550 invalid data(2).\r\n").await?;
                            error!("std::str::parse() error:{:?}", e);
                            return Err(Error::new(ErrorKind::Other, "failed to parse() packet length"));
                        },
                    };
                    if len > 1024*64 as usize {
                        self.answer("550 invalid data(3).\r\n").await?;
                        None.ok_or(Error::new(ErrorKind::Other, format!("invalid length {}", len)))?;
                    }
                }
                Err(e) => {
                    error!("BLOC network error:{:?}", e);
                    self.answer("550 network error.\r\n").await?;
                    break;
                }
            }
            debug!("NATR data_length={}", len);
            match d_stream.read_exact(&mut buffer[..len]).await {
                Ok(_) => {
                    if let Err(e) = socket.send_to(&buffer[..len], &addr).await {
                        self.answer("550 relay bloc data failed.\r\n").await?;
                        return Err(Error::new(ErrorKind::Other, format!("NATR sending bloc data through udp failed:{:?}", e)));
                    }
                }
                Err(e) => {
                    error!("NATR network error:{:?}", e);
                    self.answer("550 network error.\r\n").await?;
                    break;
                }
            }
        }
        Ok(())
    }
}

async fn process(id: usize, stream: TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let mut ftp_session = FtpSession::new(id, stream).await?;
    ftp_session.answer("220 Hello\r\n").await?;
    loop {
        match ftp_session.read_ftp_command().await {
            Ok(connection_alive) => {
                if !connection_alive {
                    info!("ftp client disconnected.");
                    break;
                }
                if let Err(e) = ftp_session.process_ftp_command().await {
                    error!("session_id={},process_ftp_command() error:{:?}", id, e);
                }
                match ftp_session.status {
                    SessionStatus::Ok => continue,
                    _ => break,
                }
            } 
            Err(e) => {
                error!("read_ftp_command() failed:{:?}", e);
                break;
            }
        }
    }
    Ok(())
}

fn run(pp: util::ProgParam, config:TxConfig) -> io::Result<()> {

    if config.gc.local_ftp_server_address.len()  == 0 {
        return Err(Error::new(ErrorKind::Other,"缺少local_ftp_server_address参数"));
    }
    let addr: SocketAddr = match config.gc.local_ftp_server_address.parse() {
        Ok(addr) => addr,
        Err(e) => return Err(Error::new(ErrorKind::Other, format!("无法解释local_ftp_server_address地址:{:?}",e))),
    };
    if let Err(e) = util::init_log(&pp.utx_root, &pp.prog_name, &config.gc.log_level) {
        return Err(Error::new(ErrorKind::Other, format!("初始化日志失败:{:?}",e)));
    }
    if pp.daemonize {
        util::daemonize(&pp.utx_root, &pp.prog_name).expect("daemonize失败");
    }

    let mut ftp_session_id: usize = 1;
    let server = async move {
        ConfigWrapper::set_inner(config).await;
        let listener = TcpListener::bind(addr).await.expect("绑定地址失败");

        let mut incoming = listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(socket) => {
                    info!("accepted connection from {:?}", socket.peer_addr());
                    let _ = task::Builder::new()
                        .name(format!("ftp_session_{}",ftp_session_id))
                        .spawn(async move {
                            match process(ftp_session_id, socket).await {
                                Err(e) => { error!("IO error {:?}", e); }
                                _ => { info!("ftp session {} terminated.", ftp_session_id); },
                            }
                        })
                        .map_err(|e| error!("failed to fork new task:{}", e));
                    ftp_session_id += 1;
                }
                Err(e) => { error!("accept error = {:?}", e); }
            }
        }
        Ok(())
    };

    info!("aftp server running...");
    task::block_on(server)
}

fn main() {
    let pp = util::parse_args();
    let config = util::load_config(&pp, true, false, false);
    println!("crypto={}", config.gc.crypto);

    let prog_name = pp.prog_name.clone();
    if let Err(e) = run(pp, config) {
        error!("error:{:?}", e);
        error!("{} encounter unrecoverable error, process terminated", prog_name);
        std::process::exit(-1);
    }
}

