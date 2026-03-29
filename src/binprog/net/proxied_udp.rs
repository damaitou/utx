
use std::io::{Result, Error, ErrorKind};
use std::io::Write;
use std::net::{SocketAddr, IpAddr};
use mio::net::{TcpListener, TcpStream};
use regex::Regex;
use rand::Rng;
use log::{error, warn, info, debug, trace};

pub struct TxUdpSession {
    pub channel_id: usize,
    pub tcp_id: usize,
    pub stream: TcpStream,
    pub send_seq: u16,
    pub recv_seq: u16,
    pub app_module: TcpAppModule,
}

