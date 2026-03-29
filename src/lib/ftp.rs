
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpStream, SocketAddr};
use std::net::IpAddr::{V4, V6};
use std::path::Path;
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
//use std::collections::HashMap;
use log::{error, warn, info, debug};
use socket2::{Socket, Domain, Type};
use crate::config::{ClientSetting, WordChecker, TxFileChannelConfig, FtpEncoding};
use crate::errors::*;
use crate::utx;
use crate::audit;
use crate::virus;
use crate::def::*;
use openssl::symm::{Cipher, encrypt, decrypt};
use crate::file_list_history::FileListHistory;
use crate::util;

extern crate serde;
extern crate bincode;
extern crate encoding;
use encoding::all::GBK;
use encoding::{Encoding, EncoderTrap, DecoderTrap};

#[link(name = "utx", kind = "static")]
extern "C" {
    fn bind_socket_to_interface(s: c_int, if_name: *const u8, ) -> c_int;
    fn sendfile(out_fd: c_int, in_fd: c_int, offset: *const i64, count: usize) -> isize;
}

fn do_read_to_string_with_decoding<R>(cs: &ClientSetting, reader: &mut R, s: &mut String) -> io::Result<usize>
where R: Read,
{
    match (cs.crypto, &cs.encoding) {
        (false, FtpEncoding::UTF8) => reader.read_to_string(s),
        (false, _) => {
            let mut data: Vec<u8> = Vec::new();
            let amount = reader.read_to_end(&mut data);
            do_decode_to_string(&data, &cs.encoding, s)?;
            amount
        },
        (true, _) => {
            let mut tmp = [0u8; 1];
            let mut amount = 0;
            loop {
                let (size, optional_data) = do_read(cs, reader, &mut tmp, true)?;
                if 0 == size {
                    return Ok(amount);
                }

                if let Some(data) = optional_data {
                    do_decode_to_string(&data, &cs.encoding, s)?;
                }
                amount += size;
            }
        }
    }
}

fn do_decode_to_string(src: &Vec<u8>, src_encoding: &FtpEncoding, s: &mut String) -> io::Result<()>
{
    match src_encoding {
        FtpEncoding::UTF8 => src.as_slice()
            .read_to_string(s)
            .map(|_v|Ok(()))?,
        FtpEncoding::GBK => GBK.decode_to(src, DecoderTrap::Strict, s)
            .map(|_v|Ok(()))
            .map_err(|e|io::Error::new(io::ErrorKind::Other, e))?,
    }
}

fn do_read<R>(cs: &ClientSetting, reader: &mut R, buf: &mut [u8], crypto: bool) -> io::Result<(usize, Option<Vec<u8>>)>
where R: Read,
{
    match crypto {
        false => Ok((reader.read(buf)?, None)),
        true => {
            let mut n: usize = 0;
            let n_buf = unsafe { std::slice::from_raw_parts_mut(&mut n as *mut _ as *mut u8, 8) };
            match reader.read_exact(n_buf) {
                Ok(_) => { 
                    if n > MAX_ENCRYPTED_BLOCK_SIZE { return Err(io::Error::new(io::ErrorKind::Other, "encrypted block too large")); 
                } },
                Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok((0, None)),
                Err(e) => return Err(e),
            }

            let mut encrypted = vec![0u8; n]; //TODO
            reader.read_exact(&mut encrypted[..n])?;

            let decrypted = decrypt(Cipher::aes_128_cbc(), &cs.crypto_key, Some(&cs.crypto_iv), &encrypted[..n])
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("decrypt failed:{}", e)))?;
            Ok((decrypted.len(), Some(decrypted)))
        }
    }
}

fn do_write<W>(cs: &ClientSetting, writer: &mut W, buf: &[u8], crypto: bool) -> io::Result<()> 
where W: Write,
{
    match crypto {
        false => writer.write_all(buf),
        true => {
            let encrypted = encrypt(Cipher::aes_128_cbc(), &cs.crypto_key, Some(&cs.crypto_iv), buf)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encrypt failed:{}", e)))?;
            let n: usize = encrypted.len();
            if n > MAX_ENCRYPTED_BLOCK_SIZE {
                return Err(io::Error::new(io::ErrorKind::Other, "encrypted block too large to write"));
            }
                
            let n_buf  = unsafe { std::slice::from_raw_parts(&n as *const _ as *const u8, 8) };
            writer.write_all(n_buf)?;
            writer.write_all(&encrypted)
        }
    }
}

fn do_io_copy<R,W>(
    cs: &ClientSetting, 
    reader: &mut R, 
    writer: &mut W, 
    read_crypto: bool, 
    write_crypto: bool,
    io_len: u64,
) -> io::Result<usize> 
where 
    R: Read + AsRawFd,
    W: Write + AsRawFd,
{
    //use sendfile() to improve performance if possible
    if io_len > 0 && !read_crypto  && !write_crypto {
        let out_fd = writer.as_raw_fd();
        let in_fd = reader.as_raw_fd();
        let mut to_send = io_len as usize;
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
        }
        return Ok(io_len as usize);
    }

    let mut amount: usize = 0;
    let mut buf = vec![0u8; 64*1024];
    loop {
        let (n, optional_data) = do_read(cs, reader, &mut buf, read_crypto)?;
        if 0 ==n {
            break;
        }

        let data: &[u8] = match optional_data.as_ref() {
            Some(data) => data,
            None => &buf[..n],
        };

        do_write(cs, writer, data, write_crypto)?;
        amount += n;
    }
    Ok(amount)
}

pub struct FtpStream<'a> {
    pub id: usize,
    pub channel: usize,
    pub vchannel: i64,
    pub audit: bool,
    pub fcc: &'a TxFileChannelConfig,
    pub cs: &'a ClientSetting,
    pub lh: String,
    pub tcp_stream: TcpStream,
    pub peer_addr: SocketAddr,
    //internal states
    mlsd_supported: bool,
    //for recving buffer
    buf: [u8; 4096],
    start: usize,
    end: usize,
    history: Option<FileListHistory>,
    last_invalidate_time: std::time::Instant,
}

impl<'a> FtpStream<'a> {
    pub fn new(
        utx_root: &'a str,
        id: usize, 
        fcc: &'a TxFileChannelConfig,
        cs: &'a ClientSetting, 
        lh: &'a str,
        track_peer_files: bool,
    ) -> Result<FtpStream<'a>> {
        let tcp_stream = util::create_bound_tcp_stream(&cs.bind_interface, &cs.remote_ftp_host_address)?;
        let history = match track_peer_files {
            false => None,
            true => {
                let path = format!("{}/utx/cache/cache_files_{}", utx_root, fcc.channel);
                Some(FileListHistory::new(&path))
            }
        };

        let peer_addr = tcp_stream.peer_addr()?;
        let mut stream = FtpStream {
            id: id,
            channel: fcc.channel,
            vchannel: fcc.vchannel,
            audit: fcc.audit,
            fcc: fcc,
            cs: cs,
            lh: lh.to_string(),
            tcp_stream: tcp_stream,
            peer_addr: peer_addr,
            mlsd_supported: false,
            buf: [0 as u8; 4096],
            start: 0,
            end: 0,
            history: history,
            last_invalidate_time: std::time::Instant::now(),
        };

        if !stream.expect("220")? {
            error!("{}: we're not welcomed", stream.lh);
            None.ok_or("220 not found, not welcomed by ftp-server")?;
        }

        if !stream.ftp_login()? {
            error!("{} ftp_login() failed!", stream.lh);
            None.ok_or(format!("无法创建ftp链接:登录ftp服务器{}失败",cs.remote_ftp_host_address))?;
        }

        stream.mlsd_supported = stream._ftp_mlsd_supported()?;
        if stream.mlsd_supported {
            info!("MLSD supported, use MLSD to list files.");
        }

        Ok(stream)
    }

    pub fn c_stream_only(self) -> TcpStream {
        self.tcp_stream
    }

    pub fn say(&mut self, what: &str) -> Result<()> {
        let s: String;
        let what = match self.cs.remove_duplicate_slash {
            false => what,
            true => {
                let mut v: Vec<char> = what.chars().collect();
                v.dedup_by(|a,b| *a=='/' && *b=='/');
                s = v.into_iter().collect::<String>();
                s.as_str()
            },
        };

        match &self.cs.encoding {
            FtpEncoding::UTF8 => {
                do_write(self.cs, &mut self.tcp_stream, what.as_bytes(), self.cs.crypto)
                    .chain_err(|| ErrorKind::RecoverableError(line!(),format!("say()发送FTP指令失败:{}",what)))?;
            },
            FtpEncoding::GBK => {
                let mut bytes = Vec::new();
                GBK.encode_to(what, EncoderTrap::Ignore, &mut bytes)
                    .map_err(|e|io::Error::new(io::ErrorKind::Other, e))?;
                do_write(self.cs, &mut self.tcp_stream, &bytes, self.cs.crypto)
                    .chain_err(|| ErrorKind::RecoverableError(line!(),format!("say()发送FTP指令失败(GBK):{}",what)))?;
            },
        }

        debug!("thread {} -> ftp_server '{}'", self.id, what);
        Ok(())
    }

    pub fn hear(&mut self) -> Result<String> {
        let mut line = Vec::<u8>::with_capacity(512);
        loop {
            /*if self.buf is empty(start==end), then read from network */
            if self.start == self.end {
                let (size, optional_data) = do_read(self.cs, &mut self.tcp_stream, &mut self.buf, self.cs.crypto)
                    .chain_err(||ErrorKind::RecoverableError(line!(),"读取ftp服务器失败".to_string()))?;

                if size == 0 {
                    None.ok_or(ErrorKind::RecoverableError(line!(),"对端断开了网络连接".to_string()))?;
                }
                if let Some(data) = optional_data {
                    self.buf[..size].copy_from_slice(&data);
                }

                self.start = 0;
                self.end = size;
            }

            //把\r\n之前的内容从buf往line拷贝
            let mut line_ok = false;
            while self.start < self.end {
                let c = self.buf[self.start];
                self.start += 1;
                if c == b'\n' && line.last() == Some(&b'\r') {
                   line_ok = true;
                   break;
                } else {
                    line.push(c);
                }
            }

            //成功接收了ftp指令,返回line
            if line_ok {
                let slice = &line[..line.len()-1]; //discard the last '\r'
                let resp = match &self.cs.encoding {
                    FtpEncoding::UTF8 => String::from_utf8_lossy(slice).to_string(),
                    FtpEncoding::GBK => {
                        let mut resp = String::new();
                        GBK.decode_to(slice, DecoderTrap::Strict, &mut resp).map_err(|e|io::Error::new(io::ErrorKind::Other, e))?;
                        resp
                    },
                };

                debug!("thread {} <- ftp_server '{}'", self.id, resp);
                if line.len() < 4 {
                    error!("ftp_server reply length too short");
                    None.ok_or(ErrorKind::RecoverableError(line!(),"ftp-server reply length too short".to_string()))?;
                }
                match line[3] {
                    b' ' => return Ok(resp.to_string()),
                    _ => {
                        line.clear();
                        continue; //三位代码之后并没有跟着空格,属于多行reply的情况,跳过并读取下一行
                    }
                }
            }
        }
    }

    pub fn expect(&mut self, code: &str) -> Result<bool> {
        loop {
            let response = self.hear()?; 
            match response.starts_with(code) {
                true => return Ok(true),
                false => match response.starts_with("226") {
                    true => {
                        debug!( "thread {} expect '{}' but meet '{}', skip and continue expecting", self.id, code, response);
                        continue;
                    },
                    false => {
                        warn!( "thread {} expect '{}' but get '{}'", self.id, code, response);
                        return Ok(false);
                    },
                }
            }
        }
    }

    fn ftp_login(&mut self) -> Result<bool> {
        self.say(format!("USER {}\r\n", self.cs.remote_ftp_user).as_str())?;
        if !self.expect("331")? {
            error!(
                "登录失败(1),{}: USER {} not accepted",
                self.lh, self.cs.remote_ftp_user
            );
            return Ok(false);
        }

        self.say(format!("PASS {}\r\n", self.cs.remote_ftp_password).as_str())?;
        if !self.expect("230")? {
            error!("登录失败(2),{}: login failed", self.lh);
            return Ok(false);
        }

        Ok(true)
    }

    /*pub*/ fn ftp_epsv(&mut self) -> Result<TcpStream> {
        self.say("EPSV 2\r\n")?;
        let resp = self.hear()?;
        if !resp.starts_with("229") {
            let msg = format!("被动模式失败,{} EPSV failed:'{}'", self.lh, resp);
            error!("{}", msg);
            None.ok_or(ErrorKind::RecoverableError(line!(),msg))?;
        }

        let l = resp.find('(').ok_or_else(||{
            let msg = format!("{} EPSV 结果格式错误 '{}' 没有'('", self.lh, resp);
             ErrorKind::RecoverableError(line!(),msg)
        })?;

        let r = resp.find(')').ok_or_else(||{
            let msg = format!("{} EPSV 结果格式错误 '{}' 没有')'", self.lh, resp);
            ErrorKind::RecoverableError(line!(),msg)
        })?;

        let ip_port: String = resp.chars().skip(l + 1).take(r - l - 1).collect();
        let port:u16 = ip_port.split('|').nth(3)
            .ok_or_else(||{
                let msg = format!("{} EPSV 结果格式错误 '{}' 没有端口信息", self.lh, resp);
                ErrorKind::RecoverableError(line!(), msg)
            })?
            .parse()
            .chain_err(||{
                let msg = format!("{} EPSV 结果格式错误 '{}' 数字不正确", self.lh, resp);
                ErrorKind::RecoverableError(line!(),msg)
            })?;

        //let sockaddr = std::net::SocketAddr::new(self.tcp_stream.peer_addr().chain_err(||"peer_addr() failed, peer disconnected")?.ip(), port);
        let sockaddr = std::net::SocketAddr::new(self.peer_addr.ip(), port);
        let domain = Domain::ipv6();
        let socket = Socket::new(domain, Type::stream(), None).chain_err(||"Socket::new() failed in ftp_epsv()")?;
        if self.cs.bind_interface.len() != 0 {
            let mut c_interface = self.cs.bind_interface.clone();
            c_interface.push('\0');
            let fd = socket.as_raw_fd();
            match unsafe { bind_socket_to_interface(fd, c_interface.as_ptr()) } {
                0 => {},
                _ => {
                    error!("{} bind_socket_to_interface('{}') failed.", self.lh, self.cs.bind_interface);
                    return None.ok_or(
                        ErrorKind::UnrecoverableError(line!(),format!("绑定网卡'{}'失败",self.cs.bind_interface)))?;
                },
            }
        }

        socket.connect(&socket2::SockAddr::from(sockaddr))
            .chain_err(||ErrorKind::RecoverableError(line!(),
                format!("连接EPSV返回端口[{}]:{}失败",self.peer_addr.ip().to_string(),port)))?;
        Ok(socket.into_tcp_stream())
    }

    /*pub*/ fn ftp_pasv(&mut self) -> Result<TcpStream> {
        self.say("PASV\r\n")?;
        let resp = self.hear()?;
        if !resp.starts_with("227") {
            let msg = format!("被动模式失败,{} PASV failed:'{}'", self.lh, resp);
            error!("{}", msg);
            None.ok_or(ErrorKind::RecoverableError(line!(),msg))?;
        }

        let l = resp.find('(').ok_or_else(||{
            let msg = format!(
                "{} PASV 结果格式错误 '{}' 没有'('", self.lh, resp);
             ErrorKind::RecoverableError(line!(),msg)
        })?;

        let r = resp.find(')').ok_or_else(||{
            let msg = format!(
                "{} PASV 结果格式错误 '{}' 没有')'", self.lh, resp);
            ErrorKind::RecoverableError(line!(),msg)
        })?;

        let ip_port: String = resp.chars().skip(l + 1).take(r - l - 1).collect();
        let vs: Vec<&str> = ip_port.split(',').collect();
        ensure!(vs.len() == 6, format!("{} PASV结果'{}'格式错误", self.lh, resp));
        let mut v = [0 as i32; 6];
        for i in 0..6 {
            v[i] = vs[i].parse().chain_err(||{
                    let msg = format!(
                        "{} PASV 结果格式错误 '{}' 数字不正确", self.lh, resp);
                    ErrorKind::RecoverableError(line!(),msg)
                })?;
        }

        let addr = format!("{}.{}.{}.{}:{}", v[0], v[1], v[2], v[3], v[4] * 256 + v[5]);
        let sockaddr: std::net::SocketAddr = addr.parse()
            .chain_err(||ErrorKind::UnrecoverableError(line!(), format!("PASV返回地址网络地址'{}'格式非法", addr)))?;
        let domain = Domain::ipv4();
        let socket = Socket::new(domain, Type::stream(), None).chain_err(||"Socket::new() failed in ftp_pasv()")?;
        if self.cs.bind_interface.len() != 0 {
            let mut c_interface = self.cs.bind_interface.clone();
            c_interface.push('\0');
            let fd = socket.as_raw_fd();
            match unsafe { bind_socket_to_interface(fd, c_interface.as_ptr()) } {
                0 => {},
                _ => {
                    error!("{} bind_socket_to_interface('{}') failed.", self.lh, self.cs.bind_interface);
                    return None.ok_or(
                        ErrorKind::UnrecoverableError(line!(),format!("绑定网卡'{}'失败",self.cs.bind_interface)))?;
                },
            }
        }

        socket
            .connect_timeout(&socket2::SockAddr::from(sockaddr), std::time::Duration::new(10,0))
            .chain_err(||ErrorKind::RecoverableError(line!(), format!("连接PASV返回地址{}失败",addr)))?;
        Ok(socket.into_tcp_stream())
    }

    pub fn ftp_passive(&mut self) -> Result<TcpStream> {
        match self.peer_addr.ip() {
            V4(_) => self.ftp_pasv(),
            V6(_) => self.ftp_epsv(),
        }
    }

    pub fn ftp_noop(&mut self) -> Result<bool> {
        self.say("NOOP\r\n")?;
        self.expect("200")
    }

    pub fn ftp_cwd_or_mkdir_one_by_one(&mut self, ftp_path: &str) -> Result<bool> {
        self.say(format!("CWD {}\r\n", ftp_path).as_str())?;
        if self.expect("250")? {
            return Ok(true);
        }

        //从根目录开始
        self.say("CWD /\r\n")?;
        if !self.expect("250")? {
            error!("OOPS! cannot CWD to '/'");
            return Ok(false);
        }

        //CWD不成功,那么就从头一级一级目录操作
        let paths:Vec<&str> = ftp_path.split("/").collect();
        for p in paths {
            if p.len() != 0 { 
                self.ftp_cwd_or_mkdir(p)?;
            }
        }

        Ok(true)
    }

    pub fn ftp_rename(
        &mut self,
        from_file: &str,
        to_file: &str) -> Result<bool> 
    {
        //RNFR
        self.say(format!("RNFR {}\r\n", from_file).as_str())?;
        if !self.expect("350")? {
            error!("{} RNFR {} failed.", self.lh, from_file);
            return Ok(false);
        }

        //RNTO
        self.say(format!("RNTO {}\r\n", to_file).as_str())?;
        if !self.expect("250")? {
            error!("{} RNTO {} failed.", self.lh, to_file);
            return Ok(false);
        }

        debug!("rename '{}' to '{}' ok", from_file, to_file);
        Ok(true)
    }

    pub fn ftp_cwd_or_mkdir( &mut self, ftp_path: &str,) -> Result<bool> {
        //先CWD
        self.say(format!("CWD {}\r\n", ftp_path).as_str())?;
        if self.expect("250")? {
            return Ok(true);
        } else {
            warn!("{} CWD to '{}' failed BEFORE MKD", self.lh, ftp_path);
        }

        //若CWD失败则MKD(若ftp_path为多级目录,对于不支持一次性建立多级目录的ftp_server会失败)
        self.say(format!("MKD {}\r\n", ftp_path).as_str())?;
        let resp = self.hear()?;
        debug!("{} MKD received '{}'", self.lh, resp);

        //再次尝试CWD
        self.say(format!("CWD {}\r\n", ftp_path).as_str())?;
        if !self.expect("250")? {
            error!("{} CWD to '{}' failed AFTER MKD", self.lh, ftp_path);
            return Ok(false);
        }

        return Ok(true);
    }

    /*
    pub fn ftp_put_dir<F>(&mut self, rel_path: &str, func: &F, depth: u32, truncate_empty_directory: bool) ->Result<()> 
        where F: Fn(&str, u8) -> Result<()>
    {
        let ftp_abs_path = format!("/{}/{}", &self.cs.remote_ftp_root_path, rel_path);
        self.ftp_cwd_or_mkdir(&ftp_abs_path)?;
        match self.ftp_local_list(rel_path) {
            Some(v) => {
                if depth > 0 && truncate_empty_directory && v.len() == 0 {
                    //TODO rmdir empty directory
                }
                for e in v {
                    match e.0 { //is_dir
                        FTP_DIR => {
                            if !e.1.starts_with(".") { //跳过首字符为'.'的目录
                                let dir = format!("{}/{}", rel_path, e.1);
                                self.ftp_put_dir(dir.as_str(), func, depth+1, truncate_empty_directory)?;
                            }
                        }
                        FTP_FILE => { //is_file
                            let file = format!("{}/{}", rel_path, e.1);
                            debug!("{} lister pushing file '{}'", self.lh, file);
                            func(file.as_str(), e.0)?; 
                        }
                        _ => {},
                    }
                }
            }
            None => {}
        }

        Ok(())
    }
    */

    pub fn file_offset_in_line(l: &str, col_index: usize) -> (bool, usize) {
        let mut col_to_skip = col_index;
        let mut offset: usize = 0;
        let mut iter = l.chars();
        while col_to_skip > 0 {
            loop {
                match iter.next() {
                    None => return (false, 0),
                    Some(c) => {offset += 1; if c == ' ' { break;}},
                }
            }

            loop {
                match iter.next() {
                    None => return (false, 0),
                    Some(c) => {offset += 1; if c != ' ' { break;}},
                }
            }

            col_to_skip -= 1;
        }

        if offset > 0 { offset -= 1; }
        (true, offset)
    }

    pub fn ftp_mlsd(&mut self, ftp_path: &str) -> Result<Vec<(u8, String)>> {
        let mut d_stream = self.ftp_passive()?;
        self.say(format!("MLSD {}\r\n", ftp_path).as_str())?;
        if !self.expect("150")? {
            error!("thread {}: MLSD {} rejected", self.id, ftp_path);
            return Ok(Vec::new()); //todo
        }

        let mut mlsd_resp = String::new();
        do_read_to_string_with_decoding(self.cs, &mut d_stream, &mut mlsd_resp)
            .chain_err(||{ ErrorKind::RecoverableError(line!(),"无法读取MLSD结果".to_string()) })?;

        let mut v_result = Vec::new();

        /* MLSD samples:
         * modify=20210514095929;perm=fle;type=cdir;unique=803U6004130;UNIX.group=50;UNIX.mode=0755;UNIX.owner=14; .
         * modify=20210514095929;perm=fle;type=pdir;unique=803U6004130;UNIX.group=50;UNIX.mode=0755;UNIX.owner=14; ..
         * modify=20200914191459;perm=fle;type=dir;unique=803U7000B94;UNIX.group=50;UNIX.mode=0755;UNIX.owner=14; pub
         * modify=20200914191459;perm=cdmpe;type=dir;unique=803U123336E;UNIX.group=50;UNIX.mode=0331;UNIX.owner=14; uploads
         * modify=20200914191319;perm=adfr;size=224;type=file;unique=803U60BB63A;UNIX.group=50;UNIX.mode=0644;UNIX.owner=14; welcome.msg
         */
        for line in mlsd_resp.lines() {
            let pos = if let Some(val) = line.find(' ') { val+1 } else { continue };
            let (facts, name) = line.split_at(pos);

            let ty = if facts.contains("type=file") { FTP_FILE } 
                else if facts.contains("type=dir") { FTP_DIR } 
                else { continue };

            if ty == FTP_FILE {
                if let Some(history) = self.history.as_mut() {
                    //let marker = line.to_string();
                    let marker = format!("{},{}",line,ftp_path);
                    if history.hit_a_file(marker) {
                        continue; //marker already in history cache, will not be processed
                    }
                }
            }

            v_result.push((ty, name.to_string()));
        }

        //for 226
        let msg = self.hear()?;
        debug!("received '{}' after MLSD", msg);

        Ok(v_result)
    }

    pub fn ftp_list(&mut self, ftp_path: &str) -> Result<Vec<(u8, String)>> {
        let mut d_stream = self.ftp_passive()?;
        self.say(format!("LIST {}\r\n", ftp_path).as_str())?;
        if !self.expect("150")? {
            error!("thread {}: LIST {} rejected", self.id, ftp_path);
            return Ok(Vec::new()); //todo
        }

        let mut list_resp = String::new();
        do_read_to_string_with_decoding(self.cs, &mut d_stream, &mut list_resp)
            .chain_err(||{ ErrorKind::RecoverableError(line!(),"无法读取LIST结果".to_string()) })?;

        let mut v_result = Vec::new();
        for line in list_resp.lines() {
            let ty = match line.chars().next() {
                Some('d') => FTP_DIR,
                Some('y') => FTP_BLOC,
                Some('-') => FTP_FILE,
                _ => {
                    warn!("无法识别的结果行:'{}'", line);
                    continue;
                },
            };
            let rpos = match self.cs.remote_ftp_list_name_offset < 0 {  //rpos = filename offset in l
                true => line.rfind(' ').unwrap_or(0)+1,
                false => match FtpStream::file_offset_in_line(&line, self.cs.remote_ftp_list_name_offset as usize) {
                    (true, n) => n,
                    (false, _) => {
                        error!("remote_ftp_list_name_offset({}) exceed columns, please check configuration", self.cs.remote_ftp_list_name_offset);
                        error!("error line = '{}'", line);
                        continue;
                    }
                }
            };
            let name = line.chars().skip(rpos).take(line.len() - rpos).collect::<String>(); //retrive filename from line
            let name: String = name.trim_matches(|c|c == '\r' || c == '\n').to_string();
            if name == "." || name == ".." { continue; }

            if ty == FTP_FILE {
                if let Some(history) = self.history.as_mut() {
                    let marker = format!("{},{}",line,ftp_path);
                    if history.hit_a_file(marker) {
                        continue; //marker already in history cache, will not be processed
                    }
                }
            }

            v_result.push((ty, name));
        }

        //for 226
        let msg = self.hear()?;
        debug!("{} received '{}' after LIST", self.lh, msg);

        Ok(v_result)
    }

    pub fn ftp_fetch_bloc(&mut self, file: &str, us: &utx::UtxSender, fcc:&TxFileChannelConfig) -> Result<bool> {
        //PASV
        let mut d_stream = self.ftp_passive()?;

        //BJON
        self.say("BJON\r\n")?;
        if !self.expect("200")? { //todo
            error!("{} BJON '{}' rejected", self.lh, file);
            return Ok(false);
        }
        debug!("{} fetch_bloc, BJON request accepted", self.lh);

        let path = &fcc.local_root_path;
        us.send_bloc_header(fcc.channel as usize, path, &file);

        let mut len: usize;
        let mut buffer = [0 as u8; 1024*64];
        loop {
            match d_stream.read_exact(&mut buffer[..5]) {
                Ok(_) => {
                    let s = std::str::from_utf8(&buffer[..5]).map_err(|e|{
                        format!("from_utf8() failed:{:?}", e)
                    })?;
                    len = s.parse().map_err(|e|{
                        format!("str::parse() failed:{:?}", e)
                    })?;
                    if len > 1024*64 as usize {
                        None.ok_or(format!("invalid length {}", len))?;
                    } 
                }
                Err(e) => {
                    error!("BLOC network error:{:?}", e);
                    break;
                }
            }
            debug!("BLOC data_length={}", len);
            match d_stream.read_exact(&mut buffer[..len]) {
                Ok(_) => {
                    us.send_bloc_buf(fcc.channel as usize, &buffer[..len], false, 1);
                }
                Err(e) => {
                    error!("BLOC network error:{:?}", e);
                    break;
                }
            }
        }
        Ok(true)
     }

    fn filetype_not_allowed(&mut self, rel_file: &str) -> Result<()> {
        self.ftp_mark_file_as(rel_file, ".badfileext")?;
        if self.fcc.audit {
            let time = time::get_time();
            let far = audit::FileAuditRecord {
                time_sec: time.sec,
                time_nsec: time.nsec,
                side: audit::AS_TX,
                channel: self.fcc.channel as u8,
                vchannel: self.fcc.vchannel,
                event: audit::AE_FILEEXT_CHECK,
                result: audit::AR_ERROR,
                result_msg: "文件扩展名不匹配".to_string(),
                ip: self.peer_addr.ip().to_string(),
                user: self.cs.remote_ftp_user.clone(),
                file: rel_file.to_string(),
                file_size: 0,
            };
            audit::audit_f(&far);
        }
        warn!("文件'{}'没有通过文件扩展名检查", rel_file);

        Ok(())
    }

    pub fn ftp_mark_file_as(&mut self, rel_file: &str, mark: &str) -> Result<bool> {
        let (rel_path, file) = match rel_file.rfind('/') {
            Some(pos) => rel_file.split_at(pos+1),
            None => ("/", rel_file),
        };

        let ftp_path = format!("{}/{}", self.cs.remote_ftp_root_path, rel_path);

        //CWD
        self.say(format!("CWD /{}\r\n", ftp_path).as_str())?;
        if !self.expect("250")? {
            error!("{} CWD to '/{}' failed.", self.lh, ftp_path);
            return Ok(false);
        }

        //RNFR
        self.say(format!("RNFR {}\r\n", file).as_str())?;
        if !self.expect("350")? {
            error!("{} RNFR {} failed.", self.lh, file);
            return Ok(false);
        }

        //RNTO
        self.say(format!("RNTO {}{}\r\n", file, mark).as_str())?;
        if !self.expect("250")? {
            error!("{} RNTO {}{} failed.", self.lh, file, mark);
            return Ok(false);
        }

        Ok(true)
    }

    pub fn ftp_local_list(&mut self, rel_path: &str) -> Option<Vec<(u8, String)>> {
        let abs_path = format!("{}/{}", self.cs.local_root_path, rel_path);
        let path = Path::new(abs_path.as_str());
        if !path.exists() || !path.is_dir() {
            return None;
        }

        let mut v_result = Vec::new();
        for entry in path.read_dir().unwrap() {
            if let Ok(entry) = entry {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        v_result.push((FTP_DIR, entry.file_name().to_str().unwrap().to_string()));
                    } else if file_type.is_file() {
                        v_result.push((FTP_FILE, entry.file_name().to_str().unwrap().to_string()));
                    }
                }
            }
        }

        Some(v_result)
    }

    fn _ftp_create_local_dir(&self, local_dir: &str) -> Result<()> {
        if let Err(e) = std::fs::create_dir(local_dir) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                let msg = format!( "{} create directory '{}' failed: {:?}", self.lh, local_dir, e);
                error!("{}", msg);
                None.ok_or(ErrorKind::UnrecoverableError(line!(),msg))?;
            } 
        }
        Ok(())
    }

    fn _ftp_mlsd_supported(&mut self) -> Result<bool> {
        self.say("MLST .\r\n")?;
        let resp = self.hear()?;
        Ok(resp.starts_with("250"))
    }
}

impl<'a> FileTransfer for FtpStream<'a> {
    fn fetch_dir(
        &mut self, 
        rel_path: &str, 
        cbof: &CallBackOnListedFile, 
        depth: u32, 
        truncate_empty_directory:bool
    ) -> Result<()> {

        self.history.as_mut().map(|h|{
            if depth == 0 { h.start_a_fetch(); }
        });

        let ftp_path = format!("{}/{}", self.cs.remote_ftp_root_path, rel_path);
        let ftp_path = util::normalized_path(&ftp_path);

        let v = if self.mlsd_supported { self.ftp_mlsd(&ftp_path)? } else { self.ftp_list(&ftp_path)? };
        if v.len() == 0 && depth > 0 && truncate_empty_directory {
            self.rm_dir(&rel_path)?;
        }

        for e in v {
            match e.0 {
                FTP_DIR => { //is_dir
                    if !e.1.starts_with(".") { //跳过名称首字符为'.'的目录
                        let dir = format!("{}/{}", rel_path, e.1);
                        self.fetch_dir(dir.as_str(), cbof, depth+1, truncate_empty_directory)?;
                    }
                }
                FTP_FILE => {//is_file
                    let file = format!("{}/{}", rel_path, e.1);
                    debug!("{} lister pushing file '{}'", self.lh, file);
                    (cbof.callback)(file.as_str(), e.0)?; //TODO
                }
                FTP_BLOC => {//is_bloc
                    let file = format!("{}/{}", rel_path, e.1);
                    debug!("{} lister pushing file '{}'", self.lh, file);
                    (cbof.callback)(file.as_str(), e.0)?;
                }
                _ => {},
            }
        }

        if let Some(his) = self.history.as_mut() {
            if 0  == depth  && (his.this_fetch_add > 0 || self.last_invalidate_time.elapsed().as_secs() >= 600) {
                let _ = his.invalidate().map_err(|e| error!("invalidating file_list_history cache failed:{:?}", e));
                self.last_invalidate_time = std::time::Instant::now();
            }
        }
        Ok(())
    }

    fn put_dir(&mut self, rel_path: &str, cbof: &CallBackOnListedFile, depth: u32, truncate_empty_directory:bool) -> Result<()>
    {
        let ftp_abs_path = format!("/{}/{}", &self.cs.remote_ftp_root_path, rel_path);
        self.ftp_cwd_or_mkdir(&ftp_abs_path)?;
        match self.ftp_local_list(rel_path) {
            Some(v) => {
                if depth > 0 && truncate_empty_directory && v.len() == 0 {
                    //TODO rmdir empty directory
                }
                for e in v {
                    match e.0 { //is_dir
                        FTP_DIR => {
                            if !e.1.starts_with(".") { //跳过首字符为'.'的目录
                                let dir = format!("{}/{}", rel_path, e.1);
                                self.put_dir(dir.as_str(), cbof, depth+1, truncate_empty_directory)?;
                            }
                        }
                        FTP_FILE => { //is_file
                            let file = format!("{}/{}", rel_path, e.1);
                            debug!("{} lister pushing file '{}'", self.lh, file);
                            (cbof.callback)(file.as_str(), e.0)?; 
                        }
                        _ => {},
                    }
                }
            }
            None => {}
        }

        Ok(())
    }

    fn rm_dir(&mut self, rel_dir: &str) -> Result<bool> {
        self.say(format!("RMD {}/{}\r\n", self.cs.remote_ftp_root_path, rel_dir).as_str())?;
        let resp = self.hear()?;
        if resp.starts_with("250") {
            info!("RMD '{}' ok", rel_dir);
            Ok(true)
        } else {
            error!("RMD '{}' rejected, response:'{}'", rel_dir, resp);
            Ok(false)
        }
    }

    fn fetch_file(&mut self, rel_file: &str, wc: &Option<WordChecker>, scanner: &mut Option<virus::VirusScanner>) -> Result<bool> {
        if !self.fcc.allow_file_ext(rel_file) {
            self.filetype_not_allowed(rel_file)?;
            return Ok(false);
        }

        //PASV
        let mut d_stream = self.ftp_passive()?;

        //RETR
        self.say(format!("RETR {}/{}\r\n", self.cs.remote_ftp_root_path, rel_file).as_str())?;
        if !self.expect("150")? {
            error!("{} RETR '{}' rejected", self.lh, rel_file);
            return Ok(false);
        }
        debug!("{} fetch_file, RETR request accepted", self.lh);

        //Create local file
        let local_file = format!("{}/{}", self.cs.local_root_path, rel_file);
        let local_file_pulling = format!("{}.pulling", local_file);
        let mut f = util::ensure_file(&local_file_pulling, None).map_err(|e|{
            error!("create local file '{}', error:{:?}", local_file_pulling, e); e
        })?;

        const OK: u32 = 1;
        const ERR_WORD_CHECK: u32 = 2;
        const ERR_VIRUS: u32 = 3;
        const ERR_NETWORK: u32 = 4;
        const ERR_WRITE_FILE: u32 = 4;
        const ERR_RENAME_FILE: u32 = 5;
        const ERR_SCAN_FAIL: u32 = 6;
        const ERR_FILE_TYPE: u32 = 7;

        //RECV the file
        let mut result = OK;
        let mut buffer = [0 as u8; 64*1024];
        let mut fsize: usize = 0;
        loop {
            match do_read(self.cs, &mut d_stream, &mut buffer, self.cs.crypto) {
                Ok((size, optional_data)) => {
                    if size == 0 {
                        break;
                    }
                    fsize += size;


                    let data: &[u8] = match optional_data.as_ref() {
                        Some(data) => data,
                        None => &buffer[..size],
                    };

                    if let Some(wc) = wc {
                        if !wc.allow(data) {
                            error!("{} receiving file '{}' error: words check failed", self.lh, rel_file);
                            result = ERR_WORD_CHECK;
                            break;
                        }
                    }

                    if let Err(e) = f.write(data) {
                        error!("{} receiving file '{}' error: {:?}", self.lh, rel_file, e);
                        result = ERR_WRITE_FILE;
                        break;
                    }
                }
                Err(e) => {
                    error!("{} RETR, error receiving data, error:'{:?}'", self.lh, e);
                    result = ERR_NETWORK;
                    break;
                }
            }
        }
        drop(d_stream);
        drop(f);

        //read 226 message
        let msg = self.hear()?;
        info!("received '{}' for '{}'", msg, rel_file);

        if result == OK && !self.fcc.allow_file_type(&local_file_pulling) {
            result = ERR_FILE_TYPE;
            if self.audit {
                let time = time::get_time();
                let far = audit::FileAuditRecord {
                    time_sec: time.sec,
                    time_nsec: time.nsec,
                    side: audit::AS_TX,
                    channel: self.channel as u8,
                    vchannel: self.vchannel,
                    event: audit::AE_FILETYPE_CHECK,
                    result: audit::AR_ERROR,
                    result_msg: "文件类型检测不通过".to_string(),
                    ip: self.peer_addr.ip().to_string(),
                    user: self.cs.remote_ftp_user.clone(),
                    file: rel_file.to_string(),
                    file_size: fsize as i64,
                };
                audit::audit_f(&far);
            }
        }

        if result == OK && scanner.is_some() {
            match scanner.as_mut().unwrap().scan(&local_file_pulling) {
                Err(e) => {
                    error!("scanning virus failed:{:?}", e);
                    result = ERR_SCAN_FAIL;
                },
                Ok((novirus, virus_msg)) => {
                    if !novirus {
                        debug!("{} scan '{}', virus_msg={}", self.lh, rel_file, virus_msg);
                        result = ERR_VIRUS;
                        //病毒审计信息
                        if self.audit {
                            let time = time::get_time();
                            let far = audit::FileAuditRecord {
                                time_sec: time.sec,
                                time_nsec: time.nsec,
                                side: audit::AS_TX,
                                channel: self.channel as u8,
                                vchannel: self.vchannel,
                                event: audit::AE_VIRUS,
                                result: audit::AR_ERROR,
                                result_msg: virus_msg,
                                ip: self.peer_addr.ip().to_string(),
                                user: self.cs.remote_ftp_user.clone(),
                                file: rel_file.to_string(),
                                file_size: fsize as i64,
                            };
                            audit::audit_f(&far);
                        }
                     }
                }
            }
        }

        if result != OK {
            if let Err(e) = std::fs::remove_file(&local_file_pulling) {
                warn!("{} failed to remove file '{}':{:?}", self.lh, local_file_pulling, e);
            }
            match result {
                ERR_WORD_CHECK => {
                    self.ftp_mark_file_as(rel_file, ".badcontent")?;
                    if self.audit {
                        let time = time::get_time();
                        let far = audit::FileAuditRecord {
                            time_sec: time.sec,
                            time_nsec: time.nsec,
                            side: audit::AS_TX,
                            channel: self.channel as u8,
                            vchannel: self.vchannel,
                            event: audit::AE_KEYWORD_CHECK,
                            result: audit::AR_ERROR,
                            result_msg: "关键字审查失败".to_string(),
                            ip: self.peer_addr.ip().to_string(),
                            user: self.cs.remote_ftp_user.clone(),
                            file: rel_file.to_string(),
                            file_size: fsize as i64,
                        };
                        audit::audit_f(&far);
                    }
                }
                ERR_VIRUS => {
                    self.ftp_mark_file_as(rel_file, ".infected")?;
                }
                ERR_FILE_TYPE => {
                    self.ftp_mark_file_as(rel_file, ".badfiletype")?;
                }
                _ => {}
            }
        } else {
            if let Err(e) = std::fs::rename(&local_file_pulling, &local_file) {
                error!("{} failed to rename file '{}':{:?}", self.lh, local_file_pulling, e);
                result = ERR_RENAME_FILE;
            }
        }

        Ok(result == OK)
    }

    fn put_file(&mut self, rel_file: &str) -> Result<()> {
        let (rel_path, file) = match rel_file.rfind('/') {
            Some(pos) => rel_file.split_at(pos+1),
            None => ("/", rel_file),
        };
        let file_pushing = format!("{}.pushing", file);

        //CWD
        let ftp_abs_path = format!("/{}/{}", &self.cs.remote_ftp_root_path, rel_path);
        self.ftp_cwd_or_mkdir_one_by_one(&ftp_abs_path)?;

        //PASV
        let mut d_stream = self.ftp_passive()?;
        d_stream.set_nodelay(true)?;

        //STOR
        //let stor = cmd.unwrap_or("STOR");
        let stor = "STOR";
        self.say(format!("{} {}\r\n", stor, file_pushing).as_str())?;
        if !self.expect("150")? {
            error!("{} STOR '{}' 命令失败", self.lh, file_pushing);
            ensure!(false, "STOR命令失败");
        }
        debug!("{} STOR request accepted", self.lh);

        //open local file
        let abs_file = format!("{}/{}", self.cs.local_root_path, rel_file);
        let mut f = File::open(abs_file.as_str()).chain_err(||{
            let msg = format!("{} 打开本地文件'{}'失败", self.lh, abs_file);
            error!("{}", msg);
            ErrorKind::RecoverableError(line!(),msg)
        })?;
        let fsize = f.metadata()?.len();

        do_io_copy(&self.cs, &mut f, &mut d_stream, false, self.cs.crypto, fsize).map_err(|e|{
            error!("{} sending file '{}' error:'{:?}'", self.lh, rel_file, e);
            e
        })?;

        drop(d_stream);

        //waitting for 226 message
        let msg = self.hear()?;
        info!("received '{}' for '{}'", msg, rel_file);

        if !self.ftp_rename(&file_pushing, &file)? {
            warn!("rename '{}' failed, rm dst_file and retry...", rel_file);
            self.rm_file(&file)?;
            self.ftp_rename(&file_pushing, &file)?;
        }

        //记录RX文件摆渡审计记录
        if self.audit {
            let time = time::get_time();
            let far = audit::FileAuditRecord {
                time_sec: time.sec,
                time_nsec: time.nsec,
                side: audit::AS_RX,
                channel: self.channel as u8,
                vchannel: self.vchannel,
                event: audit::AE_FERRY,
                result: audit::AR_OK,
                result_msg: "".to_string(),
                ip: self.peer_addr.ip().to_string(),
                user: self.cs.remote_ftp_user.clone(),
                file: rel_file.to_string(),
                file_size: fsize as i64,
            };
            audit::audit_f(&far);
        }

        Ok(())
    }

    fn rm_file(&mut self, rel_file: &str) -> Result<bool> {
        self.say(format!("DELE {}/{}\r\n", self.cs.remote_ftp_root_path, rel_file).as_str())?;
        let resp = self.hear()?;
        if resp.starts_with("250") {
            info!("{} DELE '{}' ok", self.lh, rel_file);
            Ok(true)
        } else {
            error!("{} DELE '{}' rejected, response:'{}'", self.lh, rel_file, resp);
            Ok(false)
        }
    }

    fn rm_local_file(&mut self, rel_file: &str) -> Result<()> {
        let abs_file = format!("{}/{}", self.cs.local_root_path, rel_file);
        std::fs::remove_file(&abs_file).chain_err(|| format!("删除文件'{}'失败", abs_file) )?;
        Ok(())
    }

    fn noop(&mut self) -> Result<bool> {
        self.say("NOOP\r\n")?;
        self.expect("200")
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}


