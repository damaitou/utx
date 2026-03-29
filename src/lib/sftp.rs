
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{/*TcpStream,*/ SocketAddr};
use std::path::Path;
use log::{error, warn, info, debug};
use crate::config::{ClientSetting, WordChecker, TxFileChannelConfig};
use crate::errors::*;
use crate::audit::{self, *};
use crate::virus;
use crate::def::{*, FileTransfer};
use crate::file_list_history::FileListHistory;
use crate::util;

use ssh2;

pub struct SftpStream<'a> {
    pub id: usize,
    pub channel: usize,
    pub vchannel: i64,
    pub audit: bool,
    pub fcc: &'a TxFileChannelConfig,
    pub cs: &'a ClientSetting,
    pub lh: String,
    pub session: ssh2::Session,
    pub sftp: ssh2::Sftp,
    pub peer_addr: SocketAddr,
    history: Option<FileListHistory>,
    last_invalidate_time: std::time::Instant,
}

impl<'a> SftpStream<'a> {
    pub fn new(
        utx_root: &'a str,
        id: usize, 
        fcc: &'a TxFileChannelConfig,
        cs: &'a ClientSetting, 
        lh: &'a str,
        track_peer_files: bool,
    ) -> Result<SftpStream<'a>> {
        let history = match track_peer_files {
            false => None,
            true => {
                let path = format!("{}/utx/cache/cache_files_{}", utx_root, fcc.channel);
                Some(FileListHistory::new(&path))
            }
        };

        let tcp_stream = util::create_bound_tcp_stream(&cs.bind_interface, &cs.remote_ftp_host_address)?;
        let peer_addr = tcp_stream.peer_addr()?;

        let mut sess = ssh2::Session::new().map_err(|e|format!("create ssh2 session failed:{:?}", e))?;
        sess.set_tcp_stream(tcp_stream);
        sess.handshake()
            .map_err(|e|format!("handshake() failed:{:?}",e))?;
        sess.userauth_password(&cs.remote_ftp_user, &cs.remote_ftp_password)
            .map_err(|e|format!("userauth_password() failed:{:?}",e))?;
        let sftp = sess.sftp().map_err(|e|format!("sftp() failed:{:?}",e))?;

        let stream = SftpStream {
            id: id,
            channel: fcc.channel,
            vchannel: fcc.vchannel,
            audit: fcc.audit,
            fcc: fcc,
            cs: cs,
            lh: lh.to_string(),
            session: sess,
            sftp: sftp,
            peer_addr: peer_addr,
            history: history,
            last_invalidate_time: std::time::Instant::now(),
        };

        debug!("sftp session to '{}' established", cs.remote_ftp_host_address);
        Ok(stream)
    }

    pub fn sftp_mkdir_one_by_one(&mut self, rel_path: &str) -> Result<bool> {
        let mut remote_path = Path::new(&self.cs.remote_ftp_root_path).to_path_buf();
        let components:Vec<&str> = rel_path.split("/").collect();
        for comp in components {
            if comp.len() != 0 {
                remote_path.push(comp);
                if !self.sftp.stat(remote_path.as_path()).is_ok() {
                    self.sftp
                        .mkdir(remote_path.as_path(), 0o644)
                        .map_err(|e|format!("sftp.mkdir({:?}) error:{:?}", remote_path, e))?;
                    info!("sftp.mkdir({:?}) ok", remote_path);
                }
            }
        }

        Ok(true)
    }

    pub fn sftp_rename(
        &mut self,
        from_file: &str,
        to_file: &str) -> Result<bool> 
    {
        //let flag = ssh2::RenameFlags::OVERWRITE | ssh2::RenameFlags::ATOMIC | ssh2::RenameFlags::NATIVE;
        self.sftp
            .rename(Path::new(from_file), Path::new(to_file), /*Some(flag)*/None)
            .or_else(|_e|{
                warn!("sftp.rename({}) failed, unlink dst_file and try again..", from_file);
                self.sftp
                    .unlink(Path::new(to_file))
                    .and_then(|_|self.sftp.rename(Path::new(from_file), Path::new(to_file), /*Some(flag)*/None))
            })
            .map_err(|e| format!("sftp.rename({}) error:{:?}", from_file, e) )?;
        debug!("rename '{}' to '{}' ok", from_file, to_file);
        Ok(true)
    }

    pub fn sftp_stat_or_mkdir( &mut self, ftp_path: &str,) -> Result<bool> {
        if let Err(e) = self.sftp.stat(Path::new(ftp_path)) { //todo::判断e的类型
            self.sftp
                .mkdir(Path::new(ftp_path), 0o644) //todo::what should the mode to be?
                .map_err(|_|format!("sftp.mkdir({}) failed:{:?}", ftp_path, e))?;
        }
        Ok(true)
    }

    /*
    pub fn sftp_put_dir<F>(&mut self, rel_path: &str, func: &F) ->Result<()> 
        where F: Fn(&str, u8) -> Result<()>
        {
        let ftp_abs_path = format!("/{}/{}", &self.cs.remote_ftp_root_path, rel_path);
        self.sftp_stat_or_mkdir(&ftp_abs_path)?;
        match self.sftp_local_list(rel_path) {
        Some(v) => {
        for e in v {
        match e.0 { //is_dir
        FTP_DIR => {
        if !e.1.starts_with(".") { //跳过首字符为'.'的目录
        let dir = format!("{}/{}", rel_path, e.1);
        self.sftp_put_dir(dir.as_str(), func)?;
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

    pub fn sftp_list(&mut self, abs_path: &str) -> Result<Vec<(u8, String)>> {

        let files = self.sftp.readdir(Path::new(abs_path))
            .map_err(|e|format!("sftp.readdir({}) error:{:?}", abs_path, e))?;

        let mut result = Vec::new();
        for (path,stat) in files {
            let ty = if stat.is_dir() { FTP_DIR } else if stat.is_file() { FTP_FILE } else { continue; };
            let name = match path.file_name() {
                None => continue,
                Some(name) => name.to_string_lossy().to_string(), //todo
            };
            if name == "." || name == ".." { continue; }

            if ty == FTP_FILE {
                if let Some(history) = self.history.as_mut() {
                    //notice:: stat.atime is easy to change, should not be used
                    let marker = format!("{:?},{:?},{:?}", path, stat.size, stat.mtime);
                    if history.hit_a_file(marker) {
                        continue; //marker already in history cache, will not be processed
                    }
                }
            }
            result.push((ty, name));
        }

        Ok(result)
    }

    fn filetype_not_allowed(&mut self, rel_file: &str) -> Result<()> {
        self.sftp_mark_file_as(rel_file, ".badfileext")?;
        self.do_audit(AS_TX, AE_FILEEXT_CHECK, AR_ERROR, "文件扩展名不匹配".to_string(), rel_file.to_string(), 0);
        warn!("文件'{}'没有通过文件扩展名检查", rel_file);

        Ok(())
    }

    pub fn sftp_mark_file_as(&mut self, rel_file: &str, mark: &str) -> Result<bool> {
        let src_path = format!("{}/{}", &self.cs.remote_ftp_root_path, rel_file);
        let dst_path = format!("{}{}", src_path, mark);
        self.sftp
            .rename(Path::new(&src_path), Path::new(&dst_path), None)
            .map_err(|e|format!("sftp.rename({}) failed:{:?}", src_path, e))?;
        Ok(true)
    }

    fn _sftp_create_local_dir(&self, local_dir: &str) -> Result<()> {
        if let Err(e) = std::fs::create_dir(local_dir) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                let msg = format!( "{} create directory '{}' failed: {:?}", self.lh, local_dir, e);
                error!("{}", msg);
                None.ok_or(ErrorKind::UnrecoverableError(line!(),msg))?;
            } 
        }
        Ok(())
    }

    pub fn sftp_local_list(&mut self, rel_path: &str) -> Option<Vec<(u8, String)>> {
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

    fn do_audit(&self, side:&str, event:u32, result:u32, result_msg:String, file_name:String, file_size:i64) {
        if self.audit {
            let time = time::get_time();
            let far = audit::FileAuditRecord {
                time_sec: time.sec,
                time_nsec: time.nsec,
                side: side,
                channel: self.channel as u8,
                vchannel: self.vchannel,
                event: event,
                result: result,
                result_msg: result_msg,
                ip: self.peer_addr.ip().to_string(),
                user: self.cs.remote_ftp_user.clone(),
                file: file_name,
                file_size: file_size,
            };
            audit::audit_f(&far);
        }
    }
}

impl<'a> FileTransfer for SftpStream<'a> {
    fn fetch_dir(
        &mut self, 
        rel_path: &str, 
        cbof: &CallBackOnListedFile, 
        depth: u32, 
        truncate_empty_directory:bool
    ) -> Result<()> {
        /*
        let local_dir = format!("{}/{}", self.cs.local_root_path, rel_path);
        self._sftp_create_local_dir(&local_dir)?;
        */

        self.history.as_mut().map(|h|{
            if depth == 0 { h.start_a_fetch(); }
        });

        let ftp_path = format!("{}/{}", self.cs.remote_ftp_root_path, rel_path);
        let ftp_path = util::normalized_path(&ftp_path);
        /*
        let ftp_path = Path::new(&ftp_path)
            .canonicalize()
            .chain_err(||format!("canonicalize('{}') failed", ftp_path))?
            .to_str()
            .ok_or(format!("sftp.fetch_dir() invalid path:'{}'", ftp_path))?
            .to_string();
        */

        let v = self.sftp_list(&ftp_path)?;
        if v.len() == 0 && depth > 0 && truncate_empty_directory {
            self.rm_dir(&rel_path)?;
        }

        for (ty, name) in v {
            match ty {
                FTP_DIR => { //is_dir
                    if !name.starts_with(".") { //跳过名称首字符为'.'的目录
                        let dir = format!("{}/{}", rel_path, name);
                        self.fetch_dir(&dir, cbof, depth+1, truncate_empty_directory)?;
                    }
                }
                FTP_FILE => {//is_file
                    let file = format!("{}/{}", rel_path, name);
                    debug!("{} lister pushing file '{}'", self.lh, file);
                    (cbof.callback)(file.as_str(), ty)?; //TODO
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
    
    fn put_dir(
        &mut self, 
        rel_path: &str, 
        cbof: &CallBackOnListedFile, 
        depth: u32, 
        truncate_empty_directory:bool
    ) -> Result<()> {
        let ftp_abs_path = format!("/{}/{}", &self.cs.remote_ftp_root_path, rel_path);
        self.sftp_stat_or_mkdir(&ftp_abs_path)?;
        match self.sftp_local_list(rel_path) {
            Some(v) => {
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
    
    fn fetch_file(
        &mut self, 
        rel_file: &str, 
        wc: &Option<WordChecker>, 
        scanner: &mut Option<virus::VirusScanner>
    ) -> Result<bool> {
        if !self.fcc.allow_file_ext(rel_file) {
            self.filetype_not_allowed(rel_file)?;
            return Ok(false);
        }

        let remote_file_path = format!("{}/{}", self.cs.remote_ftp_root_path, rel_file);
        let mut remote_file = self.sftp.open(Path::new(&remote_file_path))
            .map_err(|e|format!("sftp.fetch_file({}) error:{:?}", remote_file_path, e))?;

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

        if wc.is_none() {
            fsize = io::copy(&mut remote_file, &mut f)? as usize;
        }
        else {
            loop {
                match remote_file.read(&mut buffer) {
                    Ok(size) => {
                        if size == 0 { break; }
                        fsize += size;

                        let data: &[u8] = &buffer[..size];

                        if !wc.as_ref().unwrap().allow(data) {
                            error!("{} receiving file '{}' error: words check failed", self.lh, rel_file);
                            result = ERR_WORD_CHECK;
                            break;
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
        }
        drop(f);
        drop(remote_file);

        if result == OK && !self.fcc.allow_file_type(&local_file_pulling) {
            result = ERR_FILE_TYPE;
            self.do_audit(AS_TX, AE_FILETYPE_CHECK, AR_ERROR, "不允许的文件类型".to_string(), rel_file.to_string(), fsize as i64);
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
                        self.do_audit(AS_TX, AE_VIRUS, AR_ERROR, virus_msg, rel_file.to_string(), fsize as i64); //病毒审计信息
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
                    self.sftp_mark_file_as(rel_file, ".badcontent")?;
                    self.do_audit(AS_TX, AE_KEYWORD_CHECK, AR_ERROR, "关键字审查失败".to_string(), rel_file.to_string(), fsize as i64);
                }
                ERR_VIRUS => {
                    self.sftp_mark_file_as(rel_file, ".infected")?;
                }
                ERR_FILE_TYPE => {
                    self.sftp_mark_file_as(rel_file, ".badfiletype")?;
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
        let remote_abs_path = format!("{}/{}", &self.cs.remote_ftp_root_path, rel_path);
        let remote_abs_file = format!("{}/{}", &remote_abs_path, file);
        let remote_abs_file_pushing = format!("{}/{}.pushing", &remote_abs_path, file);

        let mut dst_file = match self.sftp.create(Path::new(&remote_abs_file_pushing)) {
            Ok(file) => file,
            Err(_e) => {
                self.sftp_mkdir_one_by_one(&rel_path)?; //create directory
                self.sftp.create(Path::new(&remote_abs_file_pushing)) //then try to create file again
                    .map_err(|_|"sftp.create() failed")?
            }
        };

        //open local file
        let local_abs_file = format!("{}/{}", self.cs.local_root_path, rel_file);
        let mut f = File::open(local_abs_file.as_str()).chain_err(||{
            let msg = format!("{} 打开本地文件'{}'失败", self.lh, local_abs_file);
            error!("{}", msg);
            ErrorKind::RecoverableError(line!(),msg)
        })?;
        let fsize = f.metadata()?.len();

        let mut result = false;
        let mut err_msg = String::new();
        match std::io::copy(&mut f, &mut dst_file) {
            Ok(_amount) => { result = true; }
            Err(e) => { err_msg = format!("{} sending file '{}' error:'{:?}'", self.lh, rel_file, e); }
        }

        drop(dst_file);
        drop(f);

        if result {
            result = self
                .sftp_rename(&remote_abs_file_pushing, &remote_abs_file)
                .unwrap_or_else(|e|{ err_msg = format!("rename '{}' error:'{:?}'", rel_file, e); false });
            /*
            result = match self.sftp_rename(&remote_abs_file_pushing, &remote_abs_file) {
                Ok(res) => res,
                Err(e) => {
                    err_msg = format!("rename '{}' error:'{:?}'", rel_file, e);
                    false
                }
            }
            */
        }

        if !(result) {
            error!("{}", err_msg);
        }

        //文件摆渡审计记录
        self.do_audit(AS_RX, AE_FERRY, if result { AR_OK } else { AR_ERROR }, err_msg, rel_file.to_string(), fsize as i64);
        Ok(()) //TODO!!! what if result is false?
    }

    fn rm_dir(&mut self, rel_dir: &str) -> Result<bool>  {
        let remote_file_path = format!("{}/{}", self.cs.remote_ftp_root_path, rel_dir);
        self.sftp
            .rmdir(Path::new(&remote_file_path))
            .map_err(|e|format!("sftp rmdir({}) error:{:?}",remote_file_path, e))?;
        Ok(true)
    }
    
    fn rm_file(&mut self, rel_file: &str) -> Result<bool> {
        let remote_file_path = format!("{}/{}", self.cs.remote_ftp_root_path, rel_file);
        self.sftp
            .unlink(Path::new(&remote_file_path))
            .map_err(|e|format!("sftp unlink({}) error:{:?}", remote_file_path, e))?;
        Ok(true)
    }

    fn rm_local_file(&mut self, rel_file: &str) -> Result<()> {
        let abs_file = format!("{}/{}", self.cs.local_root_path, rel_file);
        std::fs::remove_file(&abs_file).chain_err(|| format!("删除文件'{}'失败", abs_file) )?;
        Ok(())
    }

    fn noop(&mut self) -> Result<bool> {
        Ok(true) //TODO
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}


