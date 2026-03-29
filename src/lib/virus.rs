
use log::{error, debug};
use std::os::unix::net::UnixStream;
use std::io::{Read, Write};
use crate::errors::*;

pub struct VirusScanner {
    sock_file: String,
    stream: Option<UnixStream>,
}

impl VirusScanner {
    fn connect_clamd(sock_file: &str) -> Result<UnixStream> {
        let mut stream = UnixStream::connect(sock_file)
            .chain_err(||"connect to clamd server failed.")?;
        let ping = "zIDSESSION\0zPING\0";
        stream.write(ping.as_bytes())?;

        let mut buf = [0 as u8; 64];
        let size = stream.read(&mut buf)?;
        let resp = String::from_utf8_lossy(&buf[..size]);
        debug!("zIDSESSION & zPING, repsone='{}'", resp);

        if resp.contains("PONG") {
            Ok(stream)
        } else {
            None.ok_or(format!("IDSESSION & PING clamd server failed:{}", resp))?
        } 
     }

    pub fn new(sock_file: &str) -> VirusScanner {
        VirusScanner {
            sock_file: sock_file.to_string(),
            stream: match VirusScanner::connect_clamd(sock_file) {
                Ok(stream) => Some(stream),
                Err(e) => {
                    error!("connect to '{}' failed:{:?}", sock_file, e);
                    None
                }
            }
        }
    }

    pub fn scan(&mut self, abs_file: &str) -> Result<(bool, String)> {
        let has_stream = self.stream.is_some();
        match self.scan_internal(abs_file) {
            Ok(v) => Ok(v),
            Err(e) => {
                if has_stream { 
                    //执行失败可能是连接超时了,重试一次
                    self.scan_internal(abs_file)
                } else {
                    Err(e)
                }
            }
        }
    }

    fn scan_internal(&mut self, abs_file: &str) -> Result<(bool, String)> {

        if self.stream.is_none() {
            self.stream = Some(VirusScanner::connect_clamd(&self.sock_file)?);
            //todo:: alert
        }
    
        let scan_cmd = format!("zSCAN {}\0", abs_file);
        self.stream.as_mut().unwrap().write(scan_cmd.as_bytes())
            .map_err(|e|{ self.stream = None; e })?;
        
        let mut buf = [0 as u8; 1024]; //todo:: is that long enough?
        let size = self.stream.as_mut().unwrap().read(&mut buf)
            .map_err(|e|{ self.stream = None; e })?;

        let resp = String::from_utf8_lossy(&buf[..size]);
        debug!("cmd='{}', response='{}'", scan_cmd, resp);

        let pos = match resp.rfind(':') {
            Some(pos) => pos+1,
            None => 0,
        };

        let scan_result = resp.split_at(pos).1.trim_start().trim_end_matches('\0');
        Ok((scan_result.starts_with("OK"), scan_result.to_string()))
    }
}

