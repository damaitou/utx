
extern crate serde_json;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use crate::util::errors::*;

#[derive(Debug, Clone)]
pub struct UproxyEntryTcp {
    pub local_host_port: String,
    pub target_host_port: String,
}

#[derive(Debug, Clone)]
pub struct UproxyEntrySctp {
    pub local_host_port: String,
    pub target_host_port: String,
}

#[derive(Debug, Clone)]
pub struct UproxyEntryUdp {
    pub local_host_port: String,
    pub target_host_port: String,
}

#[derive(Debug, Clone)]
pub enum UproxyEntry {
    Tcp(UproxyEntryTcp),
    Sctp(UproxyEntrySctp),
    Udp(UproxyEntryUdp),
}

#[derive(Debug, Clone)]
pub struct UproxyConfig {
    pub log_path: PathBuf,
    pub log_level: String,
    pub udp_local_host_port: String,
    pub udp_peer_host_port: String,
    pub entries: Vec<UproxyEntry>,
    /*
    pub entries_tcp: Vec<UproxyEntryTcp>,
    pub entries_sctp: Vec<UproxyEntrySctp>,
    pub entries_udp: Vec<UproxyEntryUdp>,
    */
}

impl UproxyConfig {
    pub fn new(config_file: &str) -> Result<UproxyConfig> {
        let f = File::open(config_file).chain_err(||format!("打开配置文件'{}'失败", config_file))?;
        let reader = io::BufReader::new(f);
        let text: serde_json::Value = serde_json::from_reader(reader).chain_err(||"读取配置文件失败")?;

        let log_path = match text["log_path"].as_str() {
            Some(val) => PathBuf::from(val),
            None => std::env::current_dir().unwrap_or(PathBuf::from("/tmp")),
        };

        let log_level = match text["log_level"].as_str().unwrap_or("info") {
            v@"error"|v@"warn"|v@"info"|v@"debug"|v@"trace" => v.to_string(),
            _ => {
                return None.ok_or("invalid log_level, shall be error|warn|info|debug|trace")?;
            },
        };

        let mut config = UproxyConfig {
            log_path:               log_path,
            log_level:              log_level,
            udp_local_host_port:    text["udp_local_host_port"].as_str().ok_or("缺少udp_local_host_port参数")?.to_string(),
            udp_peer_host_port:     text["udp_peer_host_port"].as_str().ok_or("缺少udp_peer_host_port参数")?.to_string(),
            entries:                Vec::new(),
            /*
            entries_tcp:            Vec::new(),
            entries_sctp:           Vec::new(),
            entries_udp:            Vec::new(),
            */
        };

        match text["proxy_entries"].as_array() {
            Some(objs) => {
                for obj in objs {
                    let entry = UproxyConfig::parse_entry(&obj)?;
                    config.entries.push(entry);
                }
            },
            None => {}
        }

        Ok(config)
    }

    fn parse_entry(obj: &serde_json::Value) -> Result<UproxyEntry> {
        match obj["protocol"].as_str().ok_or("缺少protocol参数")? {
            "tcp" => {
                let entry_tcp = UproxyEntryTcp {
                    local_host_port: obj["tcp_local_host_port"].as_str().ok_or("缺少tcp_local_host_port参数")?.to_string(),
                    target_host_port: obj["tcp_target_host_port"].as_str().ok_or("缺少tcp_target_host_port参数")?.to_string(),
                };
                Ok(UproxyEntry::Tcp(entry_tcp))
            },
            "sctp" => {
                let entry_sctp = UproxyEntrySctp {
                    local_host_port: obj["sctp_local_host_port"].as_str().ok_or("缺少sctp_local_host_port参数")?.to_string(),
                    target_host_port: obj["sctp_target_host_port"].as_str().ok_or("缺少sctp_target_host_port参数")?.to_string(),
                };
                Ok(UproxyEntry::Sctp(entry_sctp))
            }
            _ => {
                None.ok_or("不支持的protocol类型")?
            }
        }

        //Ok(entry)
    }
}

