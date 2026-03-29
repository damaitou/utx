
extern crate serde_json;
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::slice;
use std::net::{IpAddr, SocketAddr};
use log::{error,warn,trace};
use crate::util::errors::*;
use crate::net::proxied_tcp::TcpAppModule;
//use crate::license::License;

/*
pub const VERSION: &'static str = "1.0.3";
*/

#[derive(Debug, Clone)]
pub struct PhysicalInterface {
    pub pi_index: u8,
    pub if_name: String,
    pub upper_mac: String,
    pub lower_mac: String,
}

#[derive(Clone)]
pub struct BtxTcpConfig {
    pub src_hosts: Vec<(IpAddr, IpAddr)>,
    pub dst_host: String,
    pub dst_port: u16,
    pub dst_host_addr: SocketAddr,
    pub proxy_port: u16,
    pub app_module: TcpAppModule,
}
impl BtxTcpConfig {
    fn check_ip(&self, ip: &IpAddr) -> bool {
        for ip_seg in &self.src_hosts {
            if &ip_seg.0 <= ip && ip <= &ip_seg.1 {
                return true;
            }
        }
        false
    }
}

#[derive(Clone)]
pub struct BtxUdpConfig {
}

#[derive(Clone)]
pub struct BtxIcmpConfig {
}

#[derive(Clone)]
pub enum BtxDirection {
    UpperToLower,
    LowerToUpper,
}

#[derive(Clone)]
pub enum BtxProtocol {
    Tcp(BtxTcpConfig),
    Udp(BtxUdpConfig),
    Icmp(BtxIcmpConfig),
}

#[derive(Clone)]
pub struct BtxChannel {
    pub channel_id: u16,
    pub direction: BtxDirection,
    pub pi_index: u8,
    pub upper_bind_interface: Option<String>,
    pub lower_bind_interface: Option<String>,
    pub protocol: BtxProtocol,
}

impl BtxChannel {
    pub fn check_ip(&self, ip: &IpAddr) -> bool {
        match &self.protocol {
            BtxProtocol::Tcp(tcp_config) => tcp_config.check_ip(ip),
            _ => false,
        }
    }
}

#[derive(Clone)]
pub enum BtxRole {
    Proxy,
    TransparentProxy,
    Router,
}

#[derive(Clone)]
pub struct  GeneralConfig {
    pub log_level: String,
    pub role: BtxRole,
}

#[derive(Clone)]
pub struct BtxConfig {
    //pub license: String,
    pub general_config: GeneralConfig,

    pub physical_interfaces: Vec<PhysicalInterface>,
    pub channels: Vec<BtxChannel>,
    pub channel_index: HashMap<u16, usize>,
}

impl Drop for BtxConfig {
    fn drop(&mut self) {
        eprintln!("BtxConfig being dropped...");
    }
}

impl BtxConfig {

    pub fn new(config_file: &str) -> Result<BtxConfig> {
        let f = File::open(config_file).chain_err(||format!("打开配置文件'{}'失败", config_file))?;
        let reader = io::BufReader::new(f);
        let text: serde_json::Value = serde_json::from_reader(reader).chain_err(||"读取配置文件失败")?;

        let mut config = BtxConfig {
            general_config: GeneralConfig {
                log_level:  match text["log_level"].as_str().unwrap_or("info") {
                                v@"error"|v@"warn"|v@"info"|v@"debug"|v@"trace" => v.to_string(),
                                _ => {
                                    return None.ok_or("invalid log_level, shall be error|warn|info|debug|trace")?;
                                },
                            },
                role:       match text["role"].as_str().unwrap_or("proxy") {
                                "proxy" =>              BtxRole::Proxy,
                                "transparent_proxy" =>  BtxRole::TransparentProxy,
                                "router" =>             BtxRole::Router,
                                _ => {
                                    return None.ok_or("invalid role, shall be proxy|transparent_proxy|router")?;
                                }
                            },
            },
            physical_interfaces: Vec::new(),
            channels: Vec::new(),
            channel_index: HashMap::new(),
        };

        let objs = text["physical_interfaces"].as_array().ok_or("缺少physical_interfaces参数")?;
        for obj in objs {
            let pi = BtxConfig::parse_physical_interface(&obj)?;
            ensure!(config.get_conflict_mac(&pi.upper_mac).is_none(),
                format!("upper_mac='{}'被多个physical_interface同时使用",pi.upper_mac));
            ensure!(config.get_conflict_mac(&pi.lower_mac).is_none(),
                format!("lower_mac='{}'被多个physical_interface同时使用",pi.lower_mac));
            match config.get_physical_interface(pi.pi_index) {
                None => config.physical_interfaces.push(pi),
                Some(_) => {
                    None.ok_or(format!("存在多个pi_index='{}'的physical_interface配置", pi.pi_index))?;
                }
            }
        }

        let objs = text["channels"].as_array().ok_or("缺少channels参数")?;
        for obj in objs {
            let bc = BtxConfig::parse_channel(&obj)?;
            ensure!(config.get_physical_interface(bc.pi_index).is_some(),
                format!("channel#{}的pi_index='{}',没有对应的physical_interface配置",bc.channel_id, bc.pi_index));
            let channel_id = bc.channel_id;
            config.channels.push(bc);
            match config.channel_index.insert(channel_id, config.channels.len()-1) {
                None => {}
                Some(_prev) => {
                    Option::<BtxConfig>::None.ok_or(format!("存在多个channel_id={}的配置", channel_id))?;
                }
            }
        }

        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<()> {
        ensure!(self.physical_interfaces.len() > 0, "fatal!! 没有配置任何物理通信接口(physical_interfaces)");
        ensure!(self.channels.len() > 0, "fatal!! 没有配置任何通道(channels)");
        //todo::检查是否存在代理IP冲突
        Ok(())
    }

    fn parse_channel(obj: &serde_json::Value) -> Result<BtxChannel> {
        let bc = BtxChannel {
            channel_id: obj["channel_id"].as_i64().ok_or("缺少channel_id参数")? as u16,
            direction: BtxConfig::parse_direction(obj["direction"].as_str().ok_or("缺少direction参数")?)?,
            pi_index: obj["pi_index"].as_i64().ok_or("缺少pi_index参数")? as u8,
            upper_bind_interface: obj["upper_bind_interface"].as_str().map(|v|v.to_string()),
            lower_bind_interface: obj["lower_bind_interface"].as_str().map(|v|v.to_string()),
            protocol: BtxConfig::parse_protocol(&obj["protocol"])?,
        };
        Ok(bc)
    }

    fn parse_protocol(obj: &serde_json::Value) -> Result<BtxProtocol> {
        match obj["protocol_module"].as_str().ok_or("缺少protocol_module参数")? {
            "tcp" => Ok(BtxProtocol::Tcp(BtxConfig::parse_tcp_config(&obj["tcp"])?)),
            "udp" => Ok(BtxProtocol::Udp(BtxConfig::parse_udp_config(&obj["udp"])?)),
            "icmp" => Ok(BtxProtocol::Icmp(BtxConfig::parse_icmp_config(&obj["icmp"])?)),
            _ => None.ok_or("invalid protocol_module")?,
        }
    }

    fn parse_tcp_config(obj: &serde_json::Value) -> Result<BtxTcpConfig> {
        let dst_host = obj["dst_host"].as_str().ok_or("缺少dst_host参数")?;
        let dst_port = obj["dst_port"].as_i64().ok_or("缺少dst_port参数")? as u16;
        let tcp_config = BtxTcpConfig {
            src_hosts:      BtxConfig::parse_host_array(&obj["src_hosts"])?,
            dst_host:       dst_host.to_string(),
            dst_port:       dst_port,
            dst_host_addr:  SocketAddr::new(dst_host.parse::<IpAddr>().chain_err(||"invalid dst_host")?, dst_port),
            proxy_port:     obj["proxy_port"].as_i64().ok_or("缺少proxy_port参数")? as u16,
            app_module: {
                match obj["app_module"].as_str().ok_or("缺少app_module参数")? {
                    "tcp" => TcpAppModule::Tcp,
                    "ftp" => TcpAppModule::Ftp,
                    "http" => TcpAppModule::Http,
                    _ => None.ok_or("invalid app_module")?,
                }
            },
        };
        Ok(tcp_config)
    }

    fn parse_udp_config(obj: &serde_json::Value) -> Result<BtxUdpConfig> {
        None.ok_or("udp not supported yet")?
    }

    fn parse_icmp_config(obj: &serde_json::Value) -> Result<BtxIcmpConfig> {
        None.ok_or("icmp not supported yet")?
    }

    fn parse_host_array(obj: &serde_json::Value) -> Result<Vec<(IpAddr,IpAddr)>> {
        let mut v: Vec<(IpAddr,IpAddr)> = Vec::new();
        let err_msg = "invalid host: not in IP/CIDR format";
        for host in obj.as_array().ok_or("not an array")? {
            let ip_pair = BtxConfig::parse_ip_segment(host.as_str().ok_or(err_msg)?)?;
            v.push(ip_pair);
        }
        Ok(v)
    }

    fn parse_ip_segment(ip_seg_str: &str) -> Result<(IpAddr,IpAddr)> {
        let mut iter = ip_seg_str.split('-');
        let ip1 = iter.next().ok_or("invalid ip range")?.parse::<IpAddr>().chain_err(||"invalid ip")?;
        let ip2 = match iter.next() {
            None => ip1,
            Some(val) => val.parse::<IpAddr>().chain_err(||format!("invalid ip {}", val))?,
        };

        ensure!(ip1.is_ipv4() == ip2.is_ipv4(), "invalid ip range");
        match ip1<=ip2 {
            true => Ok((ip1, ip2)),
            false => Ok((ip2, ip1)),
        }
    }

    fn parse_direction(val: &str) -> Result<BtxDirection> {
        match val {
            "upper_to_lower" => Ok(BtxDirection::UpperToLower),
            "lower_to_upper" => Ok(BtxDirection::LowerToUpper),
            _ => None.ok_or("invalid direction")?,
        }
    }

    fn parse_physical_interface(obj: &serde_json::Value) -> Result<PhysicalInterface> {
        let pi = PhysicalInterface {
            pi_index: obj["pi_index"].as_i64().ok_or("缺少pi_index参数")? as u8,
            if_name: obj["interface"].as_str().unwrap_or("").to_string(),
            upper_mac: obj["upper_mac"].as_str().ok_or("缺少upper_mac参数")?.to_string(),
            lower_mac: obj["lower_mac"].as_str().ok_or("缺少lower_mac参数")?.to_string(),
        };

        Ok(pi)
    }

    fn get_physical_interface(&self, pi_index: u8) -> Option<&PhysicalInterface> {
        let mut iter = 
            self.physical_interfaces.iter()
            .filter(|pi|pi.pi_index == pi_index);
        iter.next()
    }

    fn get_conflict_mac(&self, mac: &str) -> Option<&PhysicalInterface> {
        let mut iter = 
            self.physical_interfaces.iter()
            .filter(|pi|pi.upper_mac == mac || pi.lower_mac == mac);
        iter.next()
    }

    pub fn get_channel(&self, channel_id: u16) -> Option<&BtxChannel> {
        match self.channel_index.get(&channel_id) {
            Some(index) => {
                let channel = &self.channels[*index];
                assert_eq!(channel.channel_id, channel_id);
                Some(channel)
            }
            None => None,
        }
    }
}

