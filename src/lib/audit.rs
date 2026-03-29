
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::collections::VecDeque;
use std::thread;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use chrono::{Local};
use log::{error, info, /*debug*/};
use mysql::prelude::*;
use crate::errors::*;
use crate::util;

static mut AUDITOR: &'static dyn Auditor = &NopAuditor;
const Q_LOG_THRESHOLD: usize = 10_000;

pub trait Auditor: Sync + Send {
    fn log_f(&self, record: &FileAuditRecord);
    fn log_d(&self, record: &DatagramAuditRecord);
    fn log_a(&self, record: &AlertRecord);
    fn pop_record(&self) -> Option<(char, String, usize)>;
}

struct NopAuditor;
impl Auditor for NopAuditor {
    fn log_f(&self, _: &FileAuditRecord) {}
    fn log_d(&self, _: &DatagramAuditRecord) {}
    fn log_a(&self, _: &AlertRecord) {}
    fn pop_record(&self) -> Option<(char, String, usize)> { None }
}

pub fn set_auditor(auditor: &'static dyn Auditor) {
    set_auditor_inner(|| auditor)
}

fn set_auditor_inner<F>(make_auditor: F)
where
    F: FnOnce() -> &'static dyn Auditor,
{
    unsafe {
        AUDITOR = make_auditor();
    }
}

lazy_static! {
    static ref SIMPLE_AUDITOR: SimpleAuditor = SimpleAuditor {
        inner: Mutex::new(Some(
            SimpleAuditorInner {
                do_audit: false,
                q_log: VecDeque::with_capacity(1024),
            }
        )),
    };
}

struct SimpleAuditor {
    inner: Mutex<Option<SimpleAuditorInner>>,
}
impl SimpleAuditor {
    fn set_do_audit(&self, do_audit: bool) {
        let mut inner = self.inner.lock()
            .map_err(|e|error!("failed to lock mutx:{:?}",e))
            .unwrap();
        //if let Some(ref mut inner) = *self.inner.lock().unwrap() {
        if let Some(ref mut inner) = *inner {
            inner.set_do_audit(do_audit);
        }
    }
}
impl Auditor for SimpleAuditor {
    fn log_f(&self, record: &FileAuditRecord) {
        if let Ok(line) = serde_json::to_string(&record) {
            if let Some(ref mut inner) = *self.inner.lock().unwrap() {
                inner.log_line('F', line);
            }
        }
    }

    fn log_d(&self, record: &DatagramAuditRecord) {
        if let Ok(line) = serde_json::to_string(&record) {
            if let Some(ref mut inner) = *self.inner.lock().unwrap() {
                inner.log_line('D', line);
            }
        }
     }

    fn log_a(&self, record: &AlertRecord) {
        if let Ok(line) = serde_json::to_string(&record) {
            if let Some(ref mut inner) = *self.inner.lock().unwrap() {
                inner.log_line('A', line);
            }
        }
     }

    fn pop_record(&self) -> Option<(char, String, usize)> {
        if let Some(ref mut inner) = *self.inner.lock().unwrap() {
            inner.pop_line()
        } else {
            None 
        }
    }
}
struct SimpleAuditorInner {
    do_audit: bool,
    q_log: VecDeque<(char,String)>,
}
impl SimpleAuditorInner {
    fn set_do_audit(&mut self, do_audit:bool) {
        self.do_audit = do_audit;
    }

    fn log_line(&mut self, ty: char, line: String) {
        if self.do_audit || ty =='A' {
            self.q_log.push_back((ty,line));
        }
    }

    fn pop_line(&mut self) -> Option<(char, String, usize)> {
        self.q_log.pop_front().map(|(a,b)|(a,b,self.q_log.len()))
    }
}

#[inline]
fn auditor() -> &'static dyn Auditor {
    unsafe {
        AUDITOR
    }
}
#[inline]
pub fn audit_f(record: &FileAuditRecord) {
    auditor().log_f(record);
    if record.result != AR_OK && (
        record.event == AE_KEYWORD_CHECK || record.event == AE_AFTER_TREAMENT ||
        record.event == AE_VIRUS || record.event == AE_LOST_PACKET )
    {
        let ar = AlertRecord {
            time_sec: record.time_sec,
            time_nsec: record.time_nsec,
            alert_type: ALERT_TYPE_FILE,
            channel: record.channel,
            vchannel: record.vchannel,
            side: record.side,
            event: record.event,
            alert_msg: format!("文件'{}':{}", record.file, record.result_msg),
        };
        auditor().log_a(&ar);
    }
}
#[inline]
pub fn audit_d(record: &DatagramAuditRecord) {
    auditor().log_d(record);
    if record.result != AR_OK && (
        record.event == AE_KEYWORD_CHECK || record.event == AE_AFTER_TREAMENT ||
        record.event == AE_VIRUS || record.event == AE_LOST_PACKET )
    {
        let ar = AlertRecord {
            time_sec: record.time_sec,
            time_nsec: record.time_nsec,
            alert_type: ALERT_TYPE_DATAGRAM,
            channel: record.channel,
            vchannel: record.vchannel,
            side: record.side,
            event: record.event,
            alert_msg: record.result_msg.clone(),
        };
        auditor().log_a(&ar);
    }
}

pub fn audit_alert(
    alert_type: u32,
    channel: u8,
    vchannel: i64,
    side: &'static str,
    event: u32,
    alert_msg: String,
) {
    let time = time::get_time();
    let ar = AlertRecord {
        time_sec: time.sec,
        time_nsec: time.nsec,
        alert_type: alert_type,
        channel: channel,
        vchannel: vchannel,
        side: side,
        event: event,
        alert_msg: alert_msg,
    };
    auditor().log_a(&ar);
}

pub fn start_audit(pp:&util::ProgParam, conn_str:&str, lines_per_file: usize, do_audit: bool) -> Result<()> {
    SIMPLE_AUDITOR.set_do_audit(do_audit);
    set_auditor(&*SIMPLE_AUDITOR);

    let conn = open_audit_db_mysql(conn_str)?;
    let audit_file_path = format!("{}/utx/audit/{}", pp.utx_root, pp.prog_name);
    util::ensure_path(&audit_file_path)?;

    let builder = thread::Builder::new();
    builder.name("auditor".to_string()).spawn(move||{
        audit_thread_handler(conn, &audit_file_path, lines_per_file);
    })?;
    Ok(())
}

fn open_audit_db_mysql(conn_str: &str) -> Result<mysql::Pool> {

    let conn = mysql::Pool::new(conn_str)
        .chain_err(|| "连接审计数据库失败")?;

    create_table_file_audit_log_mysql(&conn).chain_err(|| "创建审计数据表file_audit_log失败")?;
    create_table_datagram_audit_log_mysql(&conn).chain_err(|| "创建审计数据表datagram_audit_log失败")?;
    create_table_alert_log_mysql(&conn).chain_err(||"创建告警表alert_log失败")?;

    Ok(conn)
}


fn audit_thread_handler(
    mut conn: mysql::Pool,
    audit_file_path: &str,
    lines_per_file: usize,
) {
    info!("auditor thread created.");

    let mut lines: usize = 0;
    let mut file: Option<File> = renew_audit_file(audit_file_path);

    loop {
        if let Some((ty,line,q_log_len)) = auditor().pop_record() {
            let log_to_file = q_log_len>Q_LOG_THRESHOLD;
            if let Err(e) = audit_line(file.as_ref(), &mut conn, ty, line, log_to_file) {
                crate::util::log_error(&e); //todo
                continue;
            };
            
            if log_to_file {
                lines += 1;
                if lines > lines_per_file {
                    file = renew_audit_file(audit_file_path);
                    lines = 0;
                }
            }
        } else {
            thread::sleep(Duration::from_millis(100));
        }
    }
}

fn renew_audit_file(path: &str) -> Option<File> {
    let now = Local::now();
    let audit_file_name = format!("{}.current.aud", path);
    let backup_file_name = format!("{}.{}.aud", path, &now.format("%Y%m%d-%H%M%S").to_string());
    let _ = std::fs::rename(&audit_file_name, &backup_file_name);
    match File::create(&audit_file_name) {
        Ok(file) => Some(file),
        Err(e) => {
            error!("renew_audit_file('{}') error:{:?}", path, e);
            None
        }
    }
}

fn audit_line(f: Option<&File>, conn: &mut mysql::Pool, ty: char, line: String, log_to_file: bool) -> Result <()> {

    if log_to_file {
        //write AuditRecord to file
        if f.is_some() {
            let now = Local::now();
            let _ = write!( f.unwrap(), "[{}] {}\n", &now.format("%Y-%m-%d %H:%M:%S.%6f").to_string(), &line,);
        }
        return Ok(())
    }

    //insert AuditRecord into table
    match ty {
        'F' => {
            let ar: FileAuditRecord = serde_json::from_str(&line)
                .chain_err(|| format!("文件审计信息反序列化失败,line={}",&line))?;
            let mut stmt = conn.prepare(
                r"
                INSERT INTO file_audit_log(
                    `time`, channel, vchannel, side, event, result, result_msg, ip, user, file, file_size)
                VALUES(:f1,:f2,:f3,:f4,:f5,:f6,:f7,:f8,:f9,:f10,:f11)
                ",
            ).chain_err(|| "prepare for inserting file_audit_log failed.")?;
            stmt.execute(
                params!{
                    "f1" => ar.time_sec,
                    "f2" => ar.channel, 
                    "f3" => ar.vchannel, 
                    "f4" => &ar.side, 
                    "f5" => ar.event, 
                    "f6" => ar.result, 
                    "f7" => &ar.result_msg, 
                    "f8" => &ar.ip,
                    "f9" => &ar.user, 
                    "f10" => &ar.file, 
                    "f11" => ar.file_size
                },
            ).chain_err(||"文件审计信息入库失败")?;
         },
        'D' => {
            let ar:DatagramAuditRecord = serde_json::from_str(&line)
                .chain_err(|| format!("报文审计信息反序列化失败,line={}",&line))?;
            let mut stmt = conn.prepare(
                r"
                INSERT INTO datagram_audit_log(
                    `time`,channel,vchannel,side,event,result,result_msg,ip,traffic_in,traffic_out,`interval`)
                    VALUES(:f1,:f2,:f3,:f4,:f5,:f6,:f7,:f8,:f9,:f10,:f11)
                ",
            ).chain_err(|| "prepare for inserting datagram_audit_log failed.")?;
            stmt.execute(
                params!{
                    "f1" => ar.time_sec,
                    "f2" => ar.channel, 
                    "f3" => ar.vchannel, 
                    "f4" => &ar.side, 
                    "f5" => ar.event, 
                    "f6" => ar.result, 
                    "f7" => &ar.result_msg, 
                    "f8" => &ar.ip,
                    "f9" => ar.traffic_in, 
                    "f10" => ar.traffic_out, 
                    "f11" => ar.interval
                },
            ).chain_err(||"报文审计信息入库失败")?;
        }
        'A' => {
            let ar:AlertRecord = serde_json::from_str(&line)
                .chain_err(|| format!("告警信息反序列化失败,line={}",&line))?;
            let mut stmt = conn.prepare(
                r"
                INSERT INTO alert_log(`time`, alert_type, channel, vchannel, side, event, alert_msg) 
                VALUES(:f1,:f2,:f3,:f4,:f5,:f6,:f7)
                ",
            ).chain_err(|| "prepare for inserting alert_log failed.")?;
            stmt.execute(
                params!{
                    "f1" => ar.time_sec,
                    "f2" => ar.alert_type, 
                    "f3" => ar.channel, 
                    "f4" => ar.vchannel, 
                    "f5" => &ar.side, 
                    "f6" => ar.event, 
                    "f7" => &ar.alert_msg
                },
            ).chain_err(||"告警信息入库失败")?;
         }
        _ => {}
    }

    Ok(())
}

pub const AS_TX: &'static str = "tx";
pub const AS_RX: &'static str = "rx";

pub const AR_ERROR: u32 = 0;
pub const AR_OK: u32 = 1;

pub const AE_LOGIN: u32 = 1;                //应用端主动登录FTP(成功失败都写审计)
pub const AE_LOGOUT: u32 = 2;               //应用端主动登出FTP(成功失败都写审计)
pub const AE_UPLOAD: u32 = 3;               //应用端主动上传文件(成功失败都写审计)
pub const AE_DOWNLOAD: u32 = 4;             //应用端主动下载文件(成功失败都写审计)
pub const AE_DELETE: u32 = 5;               //应用端主动删除文件(成功失败都写审计)
pub const AE_FERRY: u32 = 6;                //文件摆渡  (成功失败都写审计)
pub const AE_KEYWORD_CHECK: u32 = 7;        //内容关键字过滤    (失败才写)
pub const AE_AFTER_TREAMENT: u32 = 8;       //后处理失败        (失败才写)
pub const AE_NO_SPACE: u32 = 9;             //空间不足          (失败才写)
pub const AE_DATAGRAM_STATS: u32 = 10;      //UDP通道流量监测   (成功才写)
pub const AE_VIRUS:u32 = 12;                //病毒检查          (失败才写)
pub const AE_FTP_CONNECT:u32 = 13;          //建立FTP链接       (失败才写)
pub const AE_LOST_PACKET:u32 = 14;          //丢包              (失败才写)
pub const AE_FILEEXT_CHECK: u32 = 15;       //文件扩展名不匹配    (失败才写)
pub const AE_FILETYPE_CHECK: u32 = 16;      //文件类型不匹配    (失败才写)

pub const ALERT_TYPE_SYS:u32 = 0;
pub const ALERT_TYPE_DATAGRAM:u32 = 1;
pub const ALERT_TYPE_FILE:u32 = 3;

#[derive(Serialize, Deserialize)]
pub struct FileAuditRecord<'a> {
    pub time_sec: i64,
    pub time_nsec: i32,
    pub channel: u8,
    pub vchannel: i64,
    pub side: &'a str,
    pub event: u32,
    pub result: u32,
    pub result_msg: String,
    pub ip: String,
    pub user: String,
    pub file: String,
    pub file_size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct DatagramAuditRecord<'a> {
    pub time_sec: i64,
    pub time_nsec: i32,
    pub channel: u8,
    pub vchannel: i64,
    pub side: &'a str,
    pub event: u32,
    pub result: u32,
    pub result_msg: String,
    pub ip: String,
    //traffic stats
    pub traffic_in: i64,
    pub traffic_out: i64,
    pub interval: u32,
}

#[derive(Serialize, Deserialize)]
pub struct AlertRecord<'a> {
    pub time_sec: i64,
    pub time_nsec: i32,
    pub alert_type: u32,
    pub channel: u8,
    pub vchannel: i64,
    pub side: &'a str,
    pub event: u32,
    pub alert_msg: String,
}

fn create_table_file_audit_log_mysql(conn: &mysql::Pool) -> Result<()> {

    match conn.prep_exec(r"select 1 from file_audit_log limit 1", ()) {
        Ok(_) => {
            return Ok(());
        }
        Err(_) => {
            info!("table 'file_audit_log' not exists, try to create...");
        }
    }

    if let Err(e) = conn.prep_exec(
        "CREATE TABLE file_audit_log (
            `id` bigint(19) NOT NULL AUTO_INCREMENT,
            `time`        bigint(19),    
            `channel`     integer,
            `vchannel`    integer,
            `side`        varchar(32),
            `event`       integer,
            `result`      integer,
            `result_msg`  text,
            `ip`          varchar(64),
            `user`        varchar(64),
            `file`        varchar(255),
            `file_size`   bigint(19),
            PRIMARY KEY (`id`)
        )",
        ()
    ) {
        eprintln!("create file_audit_log failed: {:?}",e);
        return Err(Error::with_chain(e, "create file_audit_log failed"));
    }

    info!("创建file_audit_log表成功");
    Ok(())
}

fn create_table_datagram_audit_log_mysql(conn: &mysql::Pool) -> Result<()> {

    match conn.prep_exec(r"select 1 from datagram_audit_log limit 1", ()) {
        Ok(_) => {
            return Ok(());
        }
        Err(_) => {
            info!("table 'datagram_audit_log' not exists, try to create...");
        }
    }

    if let Err(e) = conn.prep_exec(
        "CREATE TABLE datagram_audit_log (
            `id` bigint(19) NOT NULL AUTO_INCREMENT,
            `time`        bigint(19),    
            `channel`     integer,
            `vchannel`    integer,
            `side`        varchar(32),
            `event`       integer,
            `result`      integer,
            `result_msg`  text,
            `ip`          varchar(64),
            `traffic_in`  bigint(19),
            `traffic_out` bigint(19),
            `interval`    bigint(19),
            PRIMARY KEY (`id`)
        )",
        ()
    ) {
        eprintln!("create datagram_audit_log failed: {:?}",e);
        return Err(Error::with_chain(e, "create datagram_audit_log failed"));
    }

    info!("创建datagram_audit_log表成功");
    Ok(())
}

fn create_table_alert_log_mysql(conn: &mysql::Pool) -> Result<()> {

    match conn.prep_exec(r"select 1 from alert_log limit 1", ()) {
        Ok(_) => {
            return Ok(());
        }
        Err(_) => {
            info!("table 'alert_log' not exists, try to create...");
        }
    }

    if let Err(e) = conn.prep_exec(
        "CREATE TABLE alert_log (
            `id` bigint(19) NOT NULL AUTO_INCREMENT,
            `time`        bigint(19),    
            `alert_type`  integer,    
            `channel`     integer,
            `vchannel`    integer,
            `side`        varchar(32),
            `event`       integer,
            `alert_msg`   text,
            PRIMARY KEY (`id`)
        )",
        ()
    ) {
        eprintln!("create alert_log failed: {:?}",e);
        return Err(Error::with_chain(e, "create alert_log failed"));
    }

    info!("创建alert_log表成功");
    Ok(())
}

