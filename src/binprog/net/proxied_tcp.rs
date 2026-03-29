
use std::io::{Result, Error, ErrorKind};
use std::io::Write;
use std::net::{SocketAddr, IpAddr};
use mio::net::{TcpListener, TcpStream};
use regex::Regex;
use rand::Rng;
use log::{error, warn, info, debug, trace};
use crate::util::iptables::*;

pub enum FilterInputResult {
    Pass,
    //PassAndCheckResponse,
    DropSilently,
    DropAndResponse(String),
}

pub enum FilterResult {
    Pass,                                           //透传原始数据
    DropSilently,                                   //丢弃原始数据不做其他处理
    Replace(String),                                //替换原始数据
    SetupFtpDataChannel((String, TxTcpListener)),   //(new_response, Established_TxTcpListener)
}

#[derive(Debug, Clone)]
pub enum TcpAppModule {
    Tcp,
    Ftp,
    FtpData,
    //FtpData(String), //value is the original PASV result like (11,12,13,14,22,33) converted into ip:port format
    Http,
}
impl TcpAppModule {
    fn filter_data_input(&self, buf: &[u8]) -> FilterInputResult {
        match self {
            TcpAppModule::Tcp => FilterInputResult::Pass,
            TcpAppModule::Ftp => {
                //let s = unsafe { std::str::from_utf8_unchecked(buf) };
                FilterInputResult::Pass //todo
            }
            TcpAppModule::FtpData => FilterInputResult::Pass,
            TcpAppModule::Http => {
                FilterInputResult::Pass //todo
            }
        }
    }

    fn filter_data_output(&self, tcp:&TxTcpSession, buf: &[u8]) -> FilterOutputResult {
        match self {
            TcpAppModule::Tcp => FilterOutputResult::Pass,
            TcpAppModule::Ftp => {
                let re = Regex::new(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)").unwrap(); //todo::make it static
                let line = unsafe { std::str::from_utf8_unchecked(buf) };
                match re.captures(line) {
                    Some(caps) => {
                        let (oct1, oct2, oct3, oct4) = (
                            caps[1].parse::<u8>().unwrap(),
                            caps[2].parse::<u8>().unwrap(),
                            caps[3].parse::<u8>().unwrap(),
                            caps[4].parse::<u8>().unwrap()
                        );
                        let (msb, lsb) = (
                            caps[5].parse::<u8>().unwrap(),
                            caps[6].parse::<u8>().unwrap()
                        );
                        let port = ((msb as u16) << 8) + lsb as u16;
                        let dst_host_addr = format!("{}.{}.{}.{}:{}", oct1, oct2, oct3, oct4, port);
                        match dynamic_listener("PASV",0,0) {
                            Some((listener,local_port)) => {
                                let local_ip = calc_pasv_ip(&tcp.stream.local_addr().unwrap().ip()); //todo
                                let proxy_response = format!(
                                    "227 entering passive mode ({},{},{})\r\n",
                                    local_ip,
                                    local_port / 256,
                                    local_port % 256,
                                );
                                let bl = TxTcpListener {
                                    channel_id: tcp.channel_id,
                                    app_module: TcpAppModule::FtpData,
                                    dst_host_port: dst_host_addr,
                                    inner: listener,
                                };
                                FilterOutputResult::SetupFtpDataChannel((proxy_response, bl))
                            }
                            None => { 
                                FilterOutputResult::Replace("451 failed to enter paasive mode\r\n".to_string())
                            }
                        }
                    }
                    None => FilterOutputResult::Pass,
                }
            }
            TcpAppModule::FtpData => FilterOutputResult::Pass,
            TcpAppModule::Http => FilterOutputResult::Pass,
        }
    }
}

pub struct TxTcpListener {
    pub channel_id: usize,
    pub app_module: TcpAppModule,
    pub dst_host_port: String,
    pub inner: TcpListener,
}
impl Drop for TxTcpListener {
    fn drop(&mut self) {
    }
}

impl TxTcpListener {
    pub fn accept(&mut self, tcp_id: usize) -> Result<TxTcpSession> {
        let stream = self.inner.accept()?.0;
        trace!("TxTcpListener accept a stream:{:?}", stream);
        //todo:: filter the ip address
        Ok(TxTcpSession {
            channel_id: self.channel_id,
            tcp_id: tcp_id,
            stream: stream,
            send_seq: 0,
            recv_seq: 0,
            app_module: self.app_module.clone(),
        })
    }
}

pub struct TxTcpSession {
    pub channel_id: usize,
    pub tcp_id: usize,
    pub stream: TcpStream,
    pub send_seq: u16,
    pub recv_seq: u16,
    pub app_module: TcpAppModule,
}

impl TxTcpSession {
    pub fn filter_data_input(&mut self, buf: &[u8]) -> FilterInputResult {
        self.app_module.filter_data_input(buf)
        /*
        let filter_result = self.module.filter_data_input(buf);
        let buf = match &filter_result {
            FilterInputResult::Pass => data,
            FilterInputResult::DropSilently => { return; },
            FilterInputResult::DropAndResponse(response) => {
                //todo
            },
        };
        */
    }

    pub fn on_data_output(&mut self, data: &[u8]) -> Result<FilterOutputResult> {
        let filter_result = self.app_module.filter_data_output(self, data);
        let buf = match &filter_result  {
            FilterOutputResult::Pass => data,
            FilterOutputResult::DropSilently => { return Ok(filter_result); },
            FilterOutputResult::Replace(new) => new.as_bytes(),
            FilterOutputResult::SetupFtpDataChannel((replaced_response, _listener)) => {
                replaced_response.as_bytes()
            }
        };
        self.stream.write(buf).and(Ok(filter_result))
    }
}

pub struct RxTcpSession {
    pub channel: usize,
    pub tcp_id: usize,
    pub stream: Option<TcpStream>,
    pub cache: Option<([u8;64*1024], usize)>,
    pub send_seq: u16,
    pub recv_seq: u16,
}

impl RxTcpSession {
    fn cache_data(&mut self, data: &[u8]) -> usize {
        if self.cache.is_none() {
            self.cache = Some(([0;64*1024],0));
        }
        let (cache,used_len) = self.cache.as_mut().unwrap();
        let available = cache.len() - *used_len;
        let copy_len = std::cmp::min(data.len(), available);
        trace!("used_len={},available={},data.len()={},copy_len={}",*used_len,available,data.len(),copy_len);
        if copy_len > 0 {
            cache[*used_len..*used_len+copy_len].copy_from_slice(&data[..copy_len]);
            *used_len += copy_len
        }
        copy_len
    }

    pub fn process_data(&mut self, data: &[u8]) -> Result<()> {
        match self.stream.as_mut() {
            Some(stream) => {
                stream.write(data)?;
            }
            None => {
                let cached = self.cache_data(data);
                warn!("oops!! rx_tcp#{} got {} bytes and cache {} bytes", self.tcp_id, data.len(), cached)
            }
        }
        Ok(())
    }

    pub fn connection_complete(&mut self, stream: TcpStream) -> Result<()> {
        self.stream = Some(stream);
        if self.cache.is_some() {
            let (cache, len) = self.cache.take().unwrap();
            self.stream.as_mut().unwrap().write(&cache[..len])?;
            self.cache = None;
        }
        Ok(())
    }
}

fn dynamic_listener(cmd: &str, port_start:u16, port_range:u16) -> Option<(TcpListener, u16)> {
    //let port_start = self.gc.local_ftp_data_port_start as u16;
    //let port_range = self.gc.local_ftp_data_port_range as u16;
    for _i in 0..10 {
        let port = 
            match port_range == 0 {
                true => 0,
                false => rand::thread_rng().gen_range(port_start, port_start+port_range),
            };

        let bind_addr = match cmd {
            "PASV" => format!("0.0.0.0:{}", port), //todo
            "EPSV" => format!("[::]:{}", port),
            _ => unreachable!(),
        };

        debug!("trying port '{}'..._i={}", port, _i);
        let listener = match TcpListener::bind(&bind_addr.parse::<SocketAddr>().unwrap()) {
            Ok(l) => l,
            Err(e) => {
                error!("TcpListener::bind() port '{}' failed:{:?}", port, e);
                continue;
            }
        };
        let local_port = match port == 0 {
            false => port,
            true =>  {
                match listener.local_addr() {
                    Ok(la) => la.port(),
                    Err(e) => {
                        error!("TcpListener.local_addr() failed:{:?}", e);
                        continue;
                    }
                }
            }
        };

        return Some((listener, local_port));
    }

    None
}

fn calc_pasv_ip(ip: &IpAddr) -> String {
    let mut ip_v = match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    let len = ip_v.len();
    let v = &mut ip_v[len-4..];
    if v[0]==0 && v[1]==0 && v[2]== 0 && v[3]==0 {
        v[0] = 127;
        v[3] = 1;
    }
    format!("{},{},{},{}", v[0], v[1], v[2], v[3])
}

