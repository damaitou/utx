use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::os::raw::c_int;
use std::slice;
use log::{error,warn,trace};
use crate::errors::*;
use base64;

pub const VERSION: &'static str = "1.2.3";
pub const AUDIT_PATH: &'static str = "/utx/audit";
pub const DB_PATH: &'static str = "/utx/audit/";
pub const DB_FILE: &'static str = "/utx/audit/audit.db";
pub const LOG_PATH: &'static str = "/utx/log/";
pub const UNIX_PATH: &'static str = "/utx/unix/";
pub const CACHE_PATH: &'static str = "/utx/cache/";

pub const FLOW_STATISTICS_INTERVAL:u32 = 30;

const PERMISSION_DENY: u32 = 0;
const PERMISSION_ALLOW: u32 = 1;

pub const INVALID_INDEX: usize = 9999;
pub const SIDE_TX: u32 = 0;
pub const SIDE_RX: u32 = 1;

pub const AR_KEEP: u32 = 0;
pub const AR_MOVE: u32 = 1;
pub const AR_DELETE_FILE: u32 = 2;
pub const AR_DELETE_FILE_AND_DIRECTORY: u32 = 3;

pub const BLOC_SIZE : u32 = 819200;

#[link(name = "trie", kind = "static")]
extern "C" {
    fn trie_new() -> u64;
    fn trie_insert(handle: u64, word: *const u8);
    fn trie_match(handle: u64, buf: *const u8, len: i32) -> i32;
    //fn trie_drop(handle: u64);
}

#[link(name = "filemagic", kind = "static")]
extern "C" {
    fn file_magic_init() -> u64;
    fn file_magic(handle:u64, file: *const u8, len: *mut c_int) -> *const u8;
}

//todo::how to Clone WordChecker
#[derive(Debug, Clone)]
pub struct WordChecker {
    handle: u64,
    permission: u32,
}

/*
impl Drop for WordChecker {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                //trace!("dropping WordChecker({})...", handle);
                trie_drop(self.handle);
                self.handle = 0;
            }
        }
    }
}
*/

impl WordChecker {
    pub fn new() -> Option<WordChecker> {
        unsafe {
            let handle = trie_new();
            match handle {
                0 => {
                    return None;
                }
                h => {
                    let wc = WordChecker {
                        handle: h,
                        permission: PERMISSION_DENY,
                    };
                    return Some(wc);
                }
            }
        }
    }

    pub fn insert(&self, word: &str) {
        let mut w = word.to_string();
        w.push('\0');
        unsafe {
            trie_insert(self.handle, w.as_ptr());
        }
    }

    fn exist(&self, buf: &[u8]) -> bool {
        unsafe {
            return match trie_match(self.handle, buf.as_ptr(), buf.len() as i32) {
                1 => true,
                _ => false,
            };
        }
    }

    pub fn allow(&self, buf: &[u8]) -> bool {
        let exists = self.exist(buf);
        return exists && (self.permission == PERMISSION_ALLOW)
            || !exists && (self.permission == PERMISSION_DENY);
    }
}

#[derive(Debug, Clone)]
pub struct FileExtChecker {
    pub file_ext_list: String,
    pub permission: u32,
}
impl FileExtChecker{
    pub fn allow(&self, ext: &str) -> bool {
        let ext_inner = format!("${}", ext);
        trace!("FileExtChecker::allow(),ext_inner={}, file_ext_list={}", ext_inner, self.file_ext_list);
        match self.file_ext_list.find(&ext_inner) {
            Some(_) => self.permission == PERMISSION_ALLOW,
            None => self.permission == PERMISSION_DENY,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileTypeChecker {
    pub handle: u64,
    pub file_type_list: String,
    pub permission: u32,
}
impl FileTypeChecker{
    pub fn allow(&self, ty: &str) -> bool {
        let type_inner = format!("${}", ty);
        match self.file_type_list.find(&type_inner) {
            Some(_) => self.permission == PERMISSION_ALLOW,
            None => self.permission == PERMISSION_DENY,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ChannelMode {
    Internal(InternalSetting),
    Server(ServerSetting),
    ClientPull(ClientSetting),
    ClientPush(ClientSetting),
    ClientPullSftp(ClientSetting),
    ClientPushSftp(ClientSetting),
    ClientPullAgent(ClientSetting),
    ClientPushAgent(ClientSetting),
}

pub const FTP_MODE_INTERNAL: u32 = 0;
pub const FTP_MODE_SERVER: u32 = 1;
pub const FTP_MODE_CLIENT_PULL: u32 = 2;
pub const FTP_MODE_CLIENT_PUSH: u32 = 3;

#[derive(Debug, Clone)]
pub enum FtpEncoding {
    UTF8,
    GBK,
}

#[derive(Debug, Clone)]
pub struct ClientSetting {
    pub remote_ftp_host_address: String,
    pub remote_ftp_user: String,
    pub remote_ftp_password: String,
    pub remote_ftp_root_path: String,
    pub remote_ftp_list_name_offset: i64, //for tx side only
    pub remote_ftp_after_treament: u32, //for tx side only
    pub local_root_path: String,
    pub threads_number: u32,
    pub scan_interval: u32,
    pub bind_interface: String, //绑定哪个网卡
    pub crypto: bool,
    pub crypto_key: Vec<u8>,
    pub crypto_iv: Vec<u8>,
    pub encoding: FtpEncoding,
    pub remove_duplicate_slash: bool,
}

#[derive(Debug, Clone)]
pub struct InternalSetting {
    pub local_root_path: String,
}

#[derive(Debug, Clone)]
pub struct ServerSetting {
    pub local_ftp_user: String,
    pub local_ftp_password: String,
    pub local_ftp_file_permission: u32,
    pub local_root_path: String,
    pub threads_number: u32,
    pub allow_ips: Option<Vec<std::net::IpAddr>>, 
}

const RESERVED_PI_INDEX: u32 = 0;
#[derive(Debug, Clone)]
pub struct TxFileChannelConfig {
    pub channel: usize,
    pub vchannel: i64,
    pub pi_index: u32,
    pub mode: ChannelMode,
    pub scan_virus: bool,
    pub word_checker: Option<WordChecker>,
    pub file_ext_checker: Option<FileExtChecker>,
    pub file_type_checker: Option<FileTypeChecker>,
    pub after_treament: u32,
    pub local_root_path: String,
    pub relay_ip: String,
    pub relay_port: u16,
    pub audit: bool,
    pub flow_limit: usize, //unit:KB, 0 means unlimited
}

impl TxFileChannelConfig {
    pub fn allow_file_ext(&self, file: &str) -> bool {
        match self.file_ext_checker.as_ref() {
            None => true,
            Some(checker) => {
                match file.rfind('.') {
                    None => checker.permission == PERMISSION_DENY,
                    Some(pos) => {
                        let (_,ext) = file.split_at(pos+1);
                        trace!("allow_file_ext():file={},ext={}", file, ext);
                        checker.allow(ext)
                    }
                }
            }
        }
    }
    pub fn allow_file_type(&self, abs_file: &str) -> bool {
        match self.file_type_checker.as_ref() {
            None => true,
            Some(checker) => {
                let mut c_file = abs_file.to_string();
                c_file.push('\0');
                let mut len:c_int = 0;
                let ty = unsafe { file_magic(checker.handle, c_file.as_ptr(), &mut len as *mut c_int) };
                let ty = unsafe { std::str::from_utf8(slice::from_raw_parts(ty, len as usize)).unwrap() };
                trace!("allow_file_type():file={},type={}",abs_file,ty);
                checker.allow(ty)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Role {
    Server,
    Client,
}
#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Ftp,
}
#[derive(Debug, Clone)]
pub struct TcpChannelConfig {
    pub channel: usize,
    pub vchannel: i64,
    pub pi_index: u32,
    pub protocol: Protocol,
    pub role: Role,
    pub host: String,
    pub port: u16,
    pub allow_ips: Option<Vec<std::net::IpAddr>>,
    pub audit: bool,
    pub flow_limit: usize, //unit:KB, 0 means unlimited
    pub bind_interface: String,
}

#[derive(Debug, Clone)]
pub struct TxDatagramChannelConfig {
    pub channel: usize,
    pub vchannel: i64,
    pub pi_index: u32,
    pub host: String,
    pub port: u16,
    pub word_checker: Option<WordChecker>,
    pub allow_ips: Option<Vec<std::net::IpAddr>>,
    pub audit: bool,
    pub flow_limit: usize, //unit:KB, 0 means unlimited
    pub bind_interface: String,
    pub sndbuf_size: Option<u32>,
    pub rcvbuf_size: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PhysicalInterface {
    pub pi_index: u32,
    pub if_name: String,
    pub tx_mac: String,
    pub rx_mac: String,
}

#[derive(Debug, Clone)]
pub struct GeneralConfig {
    pub side: u32,
    pub mtu: u32,
    pub tx_busy_sleep_nanos: u64,
    pub rx_buffer_size_mb: u32,
    pub physical_interfaces: Vec<PhysicalInterface>,
    pub local_ftp_server_address: String,
    pub local_ftp_data_port_start: u16,
    pub local_ftp_data_port_range: u16,
    pub local_ftp_pasv_ip: Option<std::net::Ipv4Addr>,
    pub log_level: String,
    pub clamd_sock_file: String,
    pub audit_db_conn_string: String,
    pub crypto: bool,
    pub crypto_key: Vec<u8>,
    pub crypto_iv: Vec<u8>,
    pub do_utx: bool,
}

#[derive(Clone)]
pub struct TxConfig {
    pub license: String,
    pub gc: GeneralConfig,
    pub av_needed: bool, //if necessary to load anti-virus engine
    pub file_audit_needed: bool, //if necessary to start audit thread for file
    pub datagram_audit_needed: bool, //if necessary to start audit thread for datagram 

    pub fccs: Vec<TxFileChannelConfig>,
    channel_to_index: [usize; 256],
    user_to_channel: HashMap<String, usize>, //for server mode tfcc, map from user to channel_id

    pub dccs: Vec<TxDatagramChannelConfig>,
    channel_to_dccs_index: [usize; 256],

    pub tccs: Vec<TcpChannelConfig>,
    channel_to_tccs_index: [usize; 256],
}

impl Drop for TxConfig {
    fn drop(&mut self) {
        eprintln!("TxConfig being dropped...");
    }
}

impl GeneralConfig {
    pub fn get_physical_interface(&self, pi_index: u32) -> Option<&PhysicalInterface> {
        let mut iter = 
            self.physical_interfaces.iter()
            .filter(|pi|pi.pi_index == pi_index);
        iter.next()
    }

    pub fn get_conflict_mac(&self, mac: &str) -> Option<&PhysicalInterface> {
        let mut iter = 
            self.physical_interfaces.iter()
            .filter(|pi|pi.tx_mac == mac || pi.rx_mac == mac);
        iter.next()
    }
}

impl TxConfig {

    fn new_internal_setting( obj: &serde_json::Value,) -> Result<InternalSetting> {
        let is = InternalSetting {
            local_root_path: obj["local_root_path"].as_str()
                .ok_or("文件通道缺少internal_setting/local_root_path参数")?.to_string(),
        };
        Ok(is)
    }

    fn parse_client_setting(
        obj: &serde_json::Value,
    ) -> Result<ClientSetting> {
        let cs = ClientSetting {
            remote_ftp_host_address: obj["remote_ftp_host_address"]
                .as_str()
                .ok_or("文件通道缺少client_setting/remote_ftp_host_address参数")?
                .to_string(),
            remote_ftp_user: obj["remote_ftp_user"]
                .as_str()
                .ok_or("文件通道缺少client_setting/remote_ftp_user参数")?
                .to_string(),
            remote_ftp_password: obj["remote_ftp_password"]
                .as_str()
                .ok_or("文件通道缺少client_setting/remote_ftp_password参数")?
                .to_string(),
            remote_ftp_root_path: obj["remote_ftp_root_path"]
                .as_str()
                .ok_or("文件通道缺少client_setting/remote_ftp_root_path参数")?
                .to_string(),
            remote_ftp_list_name_offset: obj["remote_ftp_list_name_offset"].as_i64().unwrap_or(-1),
            remote_ftp_after_treament: match obj["remote_ftp_after_treament"].as_str().unwrap_or("delete").to_lowercase().as_str() {
                "delete" => AR_DELETE_FILE,
                "delete_file_and_directory" => AR_DELETE_FILE_AND_DIRECTORY,
                "keep"|_ => AR_KEEP, //AR_MOVE not supported here
            },
            local_root_path: obj["local_root_path"]
                .as_str()
                .ok_or("文件通道缺少client_setting/local_root_path参数")?
                .to_string(),
            threads_number: obj["threads_number"].as_i64().unwrap_or(1) as u32,
            scan_interval: obj["scan_interval"].as_i64().unwrap_or(1000) as u32,
            bind_interface: obj["bind_interface"].as_str().unwrap_or("").to_string(),
            crypto: obj["crypto"].as_i64().unwrap_or(0) != 0,
            crypto_key: base64::decode(obj["crypto_key"]
                .as_str()
                .unwrap_or("kjtbxCPw3XPFThb3mKmzfg=="))
                .chain_err(||"invalid crypto_key")?,
            crypto_iv: base64::decode(obj["crypto_iv"]
                .as_str()
                .unwrap_or("dB0Ej+7zWZWTS5JUCldWMg=="))
                .chain_err(||"invalid crypto_iv")?,
            encoding: match obj["encoding"].as_str().unwrap_or("utf8").to_lowercase().as_str() {
                "utf8" => FtpEncoding::UTF8,
                "gbk" => FtpEncoding::GBK,
                _ => FtpEncoding::UTF8,
            },
            remove_duplicate_slash: obj["remove_duplicate_slash"].as_i64().unwrap_or(1) != 0,
        };
        ensure!(cs.threads_number>0 && cs.threads_number<=40,
            "client_setting/threads_number超出允许范围,应在[1-30]区间内");

        Ok(cs)
    }

    fn parse_umask(umask_str: &str) -> Result<u32> {
        umask_str
            .parse::<u32>()
            .map(|mut v|{
                let o_umask = (v%10) & 0o7; v /= 10;
                let g_umask = (v%10) & 0o7; v /= 10;
                let u_umask = (v%10) & 0o7;
                (u_umask*64)|(g_umask*8)|o_umask
            })
            .chain_err(||"invalid umask")
    }

    fn parse_server_setting(
        obj: &serde_json::Value,
    ) -> Result<ServerSetting> {
        let ss = ServerSetting {
            local_ftp_user: obj["local_ftp_user"].as_str()
                .ok_or("文件通道缺少server_setting/local_ftp_user参数")?.to_string(),
            local_ftp_password: obj["local_ftp_password"].as_str()
                .ok_or("文件通道缺少server_setting/local_ftp_password参数")?.to_string(),
            local_ftp_file_permission: 0o777 & (!TxConfig::parse_umask(obj["local_ftp_umask"].as_str().unwrap_or("077"))?),
            local_root_path: obj["local_root_path"].as_str()
                .ok_or("文件通道缺少server_setting/local_root_path参数")?.to_string(),
            threads_number: obj["threads_number"].as_i64().unwrap_or(5) as u32,
            allow_ips: TxConfig::new_allow_ips(obj),
        };
        ensure!(ss.threads_number>0 && ss.threads_number<=20,
            "server_setting/threads_number超出允许范围,应在[1-20]区间内");

        Ok(ss)
    }

    fn parse_fcc(obj: &serde_json::Value) -> Result<TxFileChannelConfig> {
        let lrp:String; //local_root_path

        let channel = obj["channel"].as_i64().ok_or("文件通道缺少channel参数")? as usize;
        let vchannel = obj["vchannel"].as_i64().unwrap_or(0);
        let tmp = obj["ftp_mode"].as_str().ok_or(format!("文件通道{}缺少ftp_mode参数", channel))?;
        let mode = match tmp {
            "server" => {
                let ss = TxConfig::parse_server_setting(&obj["server_setting"])?;
                lrp = ss.local_root_path.clone();
                ChannelMode::Server(ss)
            }
            "client_pull" | "client_pull_ftp" => {
                let cs = TxConfig::parse_client_setting(&obj["client_setting"])?;
                lrp = cs.local_root_path.clone();
                ChannelMode::ClientPull(cs)
            }
            "client_push" | "client_push_ftp" => {
                let cs = TxConfig::parse_client_setting(&obj["client_setting"])?;
                lrp = cs.local_root_path.clone();
                ChannelMode::ClientPush(cs)
            }
            "client_pull_sftp" => {
                let cs = TxConfig::parse_client_setting(&obj["client_setting"])?;
                lrp = cs.local_root_path.clone();
                ChannelMode::ClientPullSftp(cs)
            }
            "client_push_sftp" => {
                let cs = TxConfig::parse_client_setting(&obj["client_setting"])?;
                lrp = cs.local_root_path.clone();
                ChannelMode::ClientPushSftp(cs)
            }
            "client_pull_agent" => {
                let cs = TxConfig::parse_client_setting(&obj["client_setting"])?;
                lrp = cs.local_root_path.clone();
                ChannelMode::ClientPullAgent(cs)
            }
            "client_push_agent" => {
                let cs = TxConfig::parse_client_setting(&obj["client_setting"])?;
                lrp = cs.local_root_path.clone();
                ChannelMode::ClientPushAgent(cs)
            }
            "internal" => {
                let is = TxConfig::new_internal_setting(&obj["internal_setting"])?;
                lrp = is.local_root_path.clone();
                ChannelMode::Internal(is)
            }
            _ => {
                return None.ok_or(format!("文件通道{}的ftp_mode参数非法", channel))?;
            }
        };

        if !lrp.starts_with("/") {
            return None.ok_or(format!("文件通道{}的local_root_path参数非法,请使用绝对路径", channel))?;
        }

        let ar = match obj["after_treament"]
            .as_str().unwrap_or("keep").to_lowercase().as_str() 
        {
            "move" => AR_MOVE,
            "delete" => AR_DELETE_FILE,
            "delete_file_and_directory" => AR_DELETE_FILE_AND_DIRECTORY,
            "keep"|_ => AR_KEEP,
        };

        let fcc = TxFileChannelConfig {
            channel: channel,
            vchannel: vchannel,
            pi_index: match obj["pi_index"].as_i64() {
                Some(v) => { ensure!(v > 0 && v < 10, format!("pi_index={},取值超过了合法范围[1-9]", v)); v as u32 }
                None => RESERVED_PI_INDEX, //映射到老式物理通道
            },
            mode: mode,
            scan_virus: obj["scan_virus"].as_i64().unwrap_or(0) != 0,
            word_checker: TxConfig::new_wc(obj),
            file_ext_checker: TxConfig::new_file_ext_checker(obj),
            file_type_checker: TxConfig::new_file_type_checker(obj),
            after_treament: ar,
            local_root_path: lrp,
            relay_ip: obj["relay_ip"].as_str().unwrap_or("").to_string(),
            relay_port:  obj["relay_port"].as_i64().unwrap_or(0) as u16,
            audit: obj["audit"].as_i64().unwrap_or(0) != 0,
            flow_limit: obj["flow_limit"].as_i64().unwrap_or(0) as usize,
        };

        Ok(fcc)
    }

    fn new_allow_ips(obj: &serde_json::Value) -> Option<Vec<std::net::IpAddr>> {
        match obj["allow_ips"].as_array() {
            None => None,
            Some(ips) => {
                let mut v = Vec::new();
                for ip in ips {
                    if let Some(ip) = ip.as_str() {
                        let ip_addr: std::net::IpAddr = match ip.parse() {
                            Ok(val) => val,
                            Err(e) => {
                                warn!("'{}' is not a valid ip address:{:?}", ip, e);
                                continue;
                            }
                        };
                        eprintln!("new_allow_ips(), add ip_addr={:?}", ip_addr);
                        match ip_addr {
                            std::net::IpAddr::V4(v4ip) => {
                                let v6 = v4ip.to_ipv6_mapped();
                                v.push(std::net::IpAddr::V6(v6));
                                v.push(ip_addr);
                            }
                            std::net::IpAddr::V6(_v6ip) => {
                                v.push(ip_addr);
                            }
                        }
                    }
                }
                if v.len() != 0 { Some(v) } else { None}
            }
        }
    }

    fn new_dcc(obj: &serde_json::Value) -> Result<TxDatagramChannelConfig> {
        let dcc = TxDatagramChannelConfig {
            channel: obj["channel"].as_i64().ok_or("报文通道缺少channel参数")? as usize,
            vchannel: obj["vchannel"].as_i64().unwrap_or(0),
            pi_index: 
                match obj["pi_index"].as_i64() {
                    Some(v) => { ensure!(v > 0 && v < 10, format!("pi_index={},取值超过了合法范围[1-9]", v)); v as u32 }
                    None => RESERVED_PI_INDEX, //映射到老式物理通道
                },
            host: obj["host"].as_str().ok_or("报文通道缺少host参数")?.to_string(),
            port: obj["port"].as_i64().ok_or("报文通道缺少port参数")? as u16,
            word_checker: TxConfig::new_wc(obj),
            allow_ips: TxConfig::new_allow_ips(obj),
            audit: obj["audit"].as_i64().unwrap_or(0) != 0,
            flow_limit: obj["flow_limit"].as_i64().unwrap_or(0) as usize,
            bind_interface: obj["bind_interface"].as_str().unwrap_or("").to_string(),
            sndbuf_size: obj["sndbuf_size"].as_i64().map(|e| e as u32),
            rcvbuf_size: obj["rcvbuf_size"].as_i64().map(|e| e as u32),
        };

        Ok(dcc)
    }

    fn new_tcc(obj: &serde_json::Value) -> Result<TcpChannelConfig> {
        let tcc = TcpChannelConfig {
            channel: obj["channel"].as_i64().ok_or("报文通道缺少channel参数")? as usize,
            vchannel: obj["vchannel"].as_i64().unwrap_or(0),
            pi_index: 
                match obj["pi_index"].as_i64() {
                    Some(v) => { ensure!(v > 0 && v < 10, format!("pi_index={},取值超过了合法范围[1-9]", v)); v as u32 }
                    None => RESERVED_PI_INDEX, //映射到老式物理通道
                },
            protocol: Protocol::Tcp,
            role:
                match obj["role"].as_str().ok_or("TCP通道缺少role参数")? {
                    "server" => Role::Server,
                    "client" => Role::Client,
                    _ => {
                        None.ok_or("role参数配置不正确,必须是'server'或者是'client'")?;
                        Role::Client //make compile happy
                    },
                },
            host: obj["host"].as_str().ok_or("TCP通道缺少host参数")?.to_string(),
            port: obj["port"].as_i64().ok_or("TCP通道缺少port参数")? as u16,
            allow_ips: TxConfig::new_allow_ips(obj),
            audit: obj["audit"].as_i64().unwrap_or(0) != 0,
            flow_limit: obj["flow_limit"].as_i64().unwrap_or(0) as usize,
            bind_interface: obj["bind_interface"].as_str().unwrap_or("").to_string(),
        };

        Ok(tcc)
    }

    fn new_wc(obj: &serde_json::Value) -> Option<WordChecker> {
        let words = match obj["words"].as_array() {
            Some(words) => {
                if words.len() == 0 { return None; };
                words
            }
            None => return None,
        };

        match WordChecker::new() {
            None => None,
            Some(mut wc) => {
                for word in words {
                    wc.insert(word.as_str().unwrap_or(""));
                }
                wc.permission = match obj["words_permission"]
                    .as_str().unwrap_or("deny").to_lowercase().as_str() 
                {
                    "allow" => PERMISSION_ALLOW,
                    _ => PERMISSION_DENY,
                };
                Some(wc)
            }
        }
    }

    fn new_file_ext_checker(obj: &serde_json::Value) -> Option<FileExtChecker> {
        let exts = match obj["file_exts"].as_array() {
            Some(exts) => {
                if exts.len() == 0 { return None; };
                exts
            }
            None => return None,
        };
        
        let mut ext_list = String::new();
        for ext in exts {
            match ext.as_str() {
                Some(ext) => {
                    ext_list += "$";
                    ext_list += ext;
                }
                None => {}
            }
        }

        let permission = match obj["file_exts_permission"]
            .as_str().unwrap_or("allow").to_lowercase().as_str() 
        {
            "allow" => PERMISSION_ALLOW,
            _ => PERMISSION_DENY,
        };

         let checker = FileExtChecker {
            file_ext_list: ext_list,
            permission: permission,
        };

        Some(checker)
    }

    fn new_file_type_checker(obj: &serde_json::Value) -> Option<FileTypeChecker> {
        let types = match obj["file_types"].as_array() {
            Some(types) => {
                if types.len() == 0 { return None; };
                types 
            }
            None => return None,
        };

        let handle = match unsafe { file_magic_init() } {
            0 => {
                error!("failed to initialize file_magic_handle");
                return None;
            }
            h => h,
        };
        
        let mut type_list = String::new();
        for ty in types {
            match ty.as_str() {
                Some(ty) => {
                    type_list += "$";
                    type_list += ty;
                }
                None => {}
            }
        }

        let permission = match obj["file_types_permission"]
            .as_str().unwrap_or("allow").to_lowercase().as_str() 
        {
            "allow" => PERMISSION_ALLOW,
            _ => PERMISSION_DENY,
        };

         let checker = FileTypeChecker {
            handle: handle,
            file_type_list: type_list,
            permission: permission,
        };

        Some(checker)
    }

    pub fn new(
        config_file: &str,
        load_fccs: bool,
        load_dccs: bool,
        load_tccs: bool,
    ) -> Result<TxConfig> {
        let f = File::open(config_file).chain_err(||format!("打开配置文件'{}'失败", config_file))?;
        let reader = io::BufReader::new(f);
        let text: serde_json::Value = 
            serde_json::from_reader(reader).chain_err(||"读取和校验配置文件失败")?;

        let side_s = text["side"].as_str().ok_or("缺少side参数")?.to_lowercase();
        let side = match side_s.as_str() {
            "tx" => SIDE_TX,
            "rx" => SIDE_RX,
            _ => {
                None.ok_or("side参数配置不正确,必须是'tx'或者是'rx'")?;
                0 //make compile happy
            }
        };
        println!("side='{}'({})", side_s, side);

        let mtu = text["mtu"].as_i64().unwrap_or(1500) as u32;
        if mtu != 1500 && mtu != 8000 {
            None.ok_or("mtu只能选择1500或者8000")?;
        }

        let mut gc = GeneralConfig {
            side: side,
            mtu: mtu,
            tx_busy_sleep_nanos: text["tx_busy_sleep_nanos"].as_i64().unwrap_or(10_000_000) as u64, //10ms
            rx_buffer_size_mb: (text["rx_buffer_size_mb"].as_i64().unwrap_or(640) as u32).max(128).min(2048),
            physical_interfaces: Vec::new(),
            local_ftp_server_address: text["local_ftp_server_address"].as_str().unwrap_or("").to_string(),
            local_ftp_data_port_start: text["local_ftp_data_port_start"].as_i64().unwrap_or(1024) as u16,
            local_ftp_data_port_range: text["local_ftp_data_port_range"].as_i64().unwrap_or(0) as u16,
            local_ftp_pasv_ip: match text["local_ftp_pasv_ip"].as_str() {
                None => None,
                Some(ip) => 
                    match ip.parse::<std::net::Ipv4Addr>() {
                        Ok(ip) => Some(ip),
                        _ => None,
                    }
            },
            log_level: text["log_level"].as_str()
                .map(|v|{
                    let v = v.to_lowercase();
                    match v.as_str() {
                        "error"|"warn"|"info"|"debug"|"trace" => v,
                        _ => "info".to_string(),
                    }
                })
                .unwrap_or("info".to_string()),
            clamd_sock_file: text["clamd_sock_file"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            audit_db_conn_string: text["audit_db_conn_string"]
                .as_str()
                .ok_or("缺少audit_db_conn_string参数")?
                .to_string(),
            crypto: text["local_ftp_server_crypto"].as_i64().unwrap_or(0) != 0,
            crypto_key: base64::decode(text["local_ftp_server_crypto_key"]
                .as_str()
                .unwrap_or("kjtbxCPw3XPFThb3mKmzfg=="))
                .chain_err(||"invalid crypto_key")?,
            crypto_iv: base64::decode(text["local_ftp_server_crypto_iv"]
                .as_str()
                .unwrap_or("dB0Ej+7zWZWTS5JUCldWMg=="))
                .chain_err(||"invalid crypto_iv")?,
            do_utx: text["do_utx"].as_i64().unwrap_or(1) != 0,
        };

        let pi_objs = text["physical_interfaces"].as_array();
        if let Some(pi_objs) = pi_objs {
            for obj in pi_objs {
                let pi = TxConfig::new_physical_interface(obj)?;
                ensure!(gc.get_conflict_mac(&pi.tx_mac).is_none(),
                        format!("tx_mac='{}'被多个physical_interface同时使用",pi.tx_mac));
                ensure!(gc.get_conflict_mac(&pi.rx_mac).is_none(),
                        format!("rx_mac='{}'被多个physical_interface同时使用",pi.rx_mac));
                match gc.get_physical_interface(pi.pi_index) {
                    None => gc.physical_interfaces.push(pi),
                    Some(_) => {
                        None.ok_or(format!("存在多个pi_index='{}'的physical_interface配置", pi.pi_index))?;
                    }
                }
            }
        }

        //为兼容老式单物理通道配置,把老式配置的(if_name, tx_mac, rx_mac)映射为pi_index=99的物理通道配置
        let if_name = text["interface"].as_str().unwrap_or("").to_string();
        let tx_mac = text["tx_mac"].as_str().unwrap_or("").to_string();
        let rx_mac = text["rx_mac"].as_str().unwrap_or("").to_string();
        if tx_mac != "" && rx_mac != "" {
            let pi = PhysicalInterface {
                pi_index: RESERVED_PI_INDEX,
                if_name: if_name.clone(),
                tx_mac: tx_mac.clone(),
                rx_mac: rx_mac.clone(),
            };
            gc.physical_interfaces.push(pi);
        }

        ensure!(gc.physical_interfaces.len() != 0, 
            "没有配置物理传输通道:[physical_interfaces]/[tx_mac]/[rx_mac]");

        let mut config = TxConfig {
            license: text["license"].as_str().unwrap_or("").to_string(),
            gc: gc,
            fccs: Vec::new(),
            channel_to_index: [INVALID_INDEX; 256],
            user_to_channel: HashMap::new(),
            av_needed: false,
            file_audit_needed: false,
            datagram_audit_needed: false,
            dccs: Vec::new(),
            channel_to_dccs_index: [INVALID_INDEX; 256],
            tccs: Vec::new(),
            channel_to_tccs_index: [INVALID_INDEX; 256],
        };

        let channels = text["file_channels"].as_array();
        if load_fccs {
            if let Some(channels) = channels {
                for ch in channels {
                    let fcc = TxConfig::parse_fcc(ch)?;
                    let mismatched =  match fcc.mode {
                        ChannelMode::ClientPush(_) => config.gc.side == SIDE_TX,
                        ChannelMode::ClientPull(_) => config.gc.side == SIDE_RX,
                        _ => false,
                    };
                    if mismatched {
                        let warn_msg = format!("文件通道{}的ftp_mode与side配置不匹配,忽略", fcc.channel);
                        eprintln!("{}", &warn_msg);
                        warn!("{}", &warn_msg);
                        continue;
                    }

                    ensure!(fcc.channel<256, "channel参数{}超过允许范围[0-255]", fcc.channel);
                    ensure!(config.gc.get_physical_interface(fcc.pi_index).is_some(),
                        format!("文件通道{}(pi_index='{}'),没有找到对应的physical_interface",fcc.channel, fcc.pi_index));
                    if let ChannelMode::Server(ss) = &fcc.mode {
                        let user = ss.local_ftp_user.clone();
                        let channel = fcc.channel;
                        ensure!(config.user_to_channel.insert(user, channel).is_none(),
                            "配置错误:2个或者以上的文件通道使用了相同的local_ftp_user参数");
                    }
                    ensure!(config.channel_to_index[fcc.channel]==INVALID_INDEX,
                        "配置错误:2个或者以上的文件通道使用了相同的channel参数");
                    config.channel_to_index[fcc.channel] = config.fccs.len();
                    config.av_needed = config.av_needed || fcc.scan_virus;
                    config.file_audit_needed = config.file_audit_needed || fcc.audit;
                    config.fccs.push(fcc);
                }
            }
        }

        if config.av_needed {
            ensure!(config.gc.clamd_sock_file.len() > 0,
                "配置错误:开启了杀毒功能但是没有配置clamd_sock_file");
        }
    
        let channels = text["datagram_channels"].as_array();
        if load_dccs {
            if let Some(channels) = channels {
                for ch in channels {
                    let dcc = TxConfig::new_dcc(ch)?;
                    ensure!(dcc.channel<256, "channel参数{}超过允许范围[0-255]", dcc.channel);
                    ensure!(config.gc.get_physical_interface(dcc.pi_index).is_some(),
                            format!("报文通道{}(pi_index='{}'),没有找到对应的physical_interface",dcc.channel, dcc.pi_index));
                    config.channel_to_dccs_index[dcc.channel] = config.dccs.len();
                    config.datagram_audit_needed = config.datagram_audit_needed || dcc.audit;
                    config.dccs.push(dcc);
                }
            }
        }

        let channels = text["tcp_channels"].as_array();
        if load_tccs {
            if let Some(channels) = channels {
                for ch in channels {
                    let tcc = TxConfig::new_tcc(ch)?;
                    //ensure!(dcc.channel<256, "channel参数{}超过允许范围[0-255]", dcc.channel);
                    ensure!(config.gc.get_physical_interface(tcc.pi_index).is_some(),
                            format!("报文通道{}(pi_index='{}'),没有找到对应的physical_interface",tcc.channel, tcc.pi_index));
                    config.channel_to_tccs_index[tcc.channel] = config.tccs.len();
                    //config.datagram_audit_needed = config.datagram_audit_needed || tcc.audit;
                    config.tccs.push(tcc);
                }
            }
        }

        Ok(config)
    }

    fn new_physical_interface(obj: &serde_json::Value) -> Result<PhysicalInterface> {
        let pi = PhysicalInterface {
            pi_index: obj["pi_index"].as_i64().ok_or("缺少pi_index参数")? as u32,
            if_name: obj["interface"].as_str().unwrap_or("").to_string(),
            tx_mac: obj["tx_mac"].as_str().ok_or("缺少tx_mac参数")?.to_string(),
            rx_mac: obj["rx_mac"].as_str().ok_or("缺少tx_mac参数")?.to_string(),
        };
        //ensure!(pi.pi_index >= 0, "pi_index不能为负数");

        Ok(pi)
    }

    pub fn get_tcc(&self, channel: usize) -> Option<&TcpChannelConfig> {
        if channel >= self.channel_to_tccs_index.len() {
            return None;
        }
        let index = self.channel_to_tccs_index[channel];
        match index < self.tccs.len() {
            true => {
                let tcc = &self.tccs[index];
                assert_eq!(tcc.channel, channel);
                Some(tcc)
            }
            false => None,
        }
    }

    pub fn get_dcc(&self, channel: usize) -> Option<&TxDatagramChannelConfig> {
        if channel >= self.channel_to_dccs_index.len() {
            return None;
        }
        let index = self.channel_to_dccs_index[channel];
        match index < self.dccs.len() {
            true => {
                let dcc = &self.dccs[index];
                assert_eq!(dcc.channel, channel);
                Some(dcc)
            }
            false => None,
        }
    }

    pub fn get_fcc(&self, channel: usize) -> Option<&TxFileChannelConfig> {
        if channel >= self.channel_to_index.len() {
            return None;
        }
        let index = self.channel_to_index[channel];
        match index < self.fccs.len() {
            true => {
                let fcc = &self.fccs[index];
                assert_eq!(fcc.channel, channel);
                Some(fcc)
            }
            false => None,
        }
    }

    pub fn get_fcc_by_user(&self, user: &String) -> Option<&TxFileChannelConfig> {
        match self.user_to_channel.get(user) {
            Some(channel) => self.get_fcc(*channel),
            None => None,
        }
    }
}

