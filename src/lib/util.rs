
use std::env;
use std::{thread, time};
use std::fs::File;
use std::mem;
use std::ffi::CString;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::raw::{c_int, c_void};
use crate::errors::*;
use crate::config::{self, TxConfig};
use crate::audit;
use log::{error, warn, info};
use daemonize::Daemonize;
use socket2::{Socket, Domain, Type};
//use std::os::unix::io::AsRawFd;

pub struct ProgParam {
    pub utx_root: String,
    pub prog_name: String,
    pub config_file: String,
    pub daemonize: bool,
}

#[link(name = "utx", kind = "static")]
extern "C" {
    fn bind_socket_to_interface(s: c_int, if_name: *const u8, ) -> c_int;
    //fn sendfile(out_fd: c_int, in_fd: c_int, offset: *const i64, count: usize) -> isize;
}

extern "C" {
    pub fn pipe(pipefd: *const c_int) -> c_int;
    pub fn write(fd: c_int, buf: *const u8, count: usize) -> isize;
    pub fn read(fd: c_int, buf: *mut u8, count: usize) -> isize;
}

pub fn c_pipe() -> Result<(i32, i32)> {
    unsafe {
        let pipefd = [0, 0];
        match pipe(pipefd.as_ptr()) {
            0 => {
                return Ok((pipefd[0] as i32, pipefd[1] as i32))
            },
            _ => {
                return None.ok_or("pipe()失败")?;
            },
        }
    }
}

pub fn c_write(fd: i32, buf: &[u8]) -> isize {
    unsafe {
        return write(fd, buf.as_ptr(), buf.len());
    }
}

pub fn c_read(fd: i32, buf: &mut [u8]) -> isize {
    unsafe {
        return read(fd, buf.as_mut_ptr(), buf.len());
    }
}

pub fn env_utx_root() -> Option<String> {
    match env::var("UTX_ROOT") {
        Ok(val) => Some(val),
        Err(_e) => {
            match env::var("HOME") {
                Ok(val) => Some(val),
                Err(_e) => None,
            }
        }
    }
}

pub fn log_error(e: &Error) {
    eprintln!("error: {}", e);
    error!("error: {}", e);
    for e in e.iter().skip(1) {
        eprintln!("caused by: {}", e);
        error!("caused by: {}", e);
    }
}

pub fn init_audit(pp: &ProgParam, conn_str: &str, do_audit:bool) {
    if let Err(e) = audit::start_audit(pp, conn_str, 10_000, do_audit) {
        log_error(&e);
        error!("encounter serious error, cannot proceed, exitting...");
        log::logger().flush();
        std::process::exit(-1); //todo::should exit?
    }
}

pub fn init_log(
    utx_root: &str,
    prog_name: &str,
    log_level: &str,
) -> Result<()> {
    let log_file = format!("{}/{}/{}.log", utx_root, config::LOG_PATH, prog_name);
    ensure_path(&log_file)?;
    flexi_logger::Logger::with_str(log_level)
        .log_to_file()
        .directory(format!("{}/{}", utx_root, config::LOG_PATH))
        .format(flexi_logger::with_thread)
        .rotate(
            flexi_logger::Criterion::Size(1024*1024*10), 
            flexi_logger::Naming::Numbers, 
            flexi_logger::Cleanup::KeepLogFiles(100)
        )
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {}", e));

    info!("{} version {} starting...", prog_name, config::VERSION);
    Ok(())
}

pub fn init_unix_listener(
    utx_root: &str,
    prog_name: &str,
) -> Result<UnixListener> {
    let sock_file = format!("{}/{}/{}.sock", utx_root, config::UNIX_PATH, prog_name);
    ensure_path(&sock_file)?;

    //必须在daemonize()后才能remove该文件,否则影响正在运行的进程
    std::fs::remove_file(&sock_file)
        .unwrap_or_else(|e|{
            match e.kind() {
                std::io::ErrorKind::NotFound => {},
                _ => warn!("删除'{}'失败:'{:?}',继续进行", sock_file, e),
            }
        });

    Ok(UnixListener::bind(&sock_file)
        .chain_err(|| "建立Unix-Socket监听失败")?)
}

pub fn unix_connect(
    utx_root: &str,
    prog_name: &str,
) -> Result<UnixStream> {
    let sock_file = format!("{}/{}/{}.sock", utx_root, config::UNIX_PATH, prog_name);
    Ok(UnixStream::connect(&sock_file)?)
}

pub fn daemonize(
    utx_root: &str,
    prog_name: &str,
) -> Result<()> {
    let pid_file = format!("{}/{}/{}.pid", utx_root, config::UNIX_PATH, prog_name);
    ensure_path(&pid_file)?;

    let daemon = Daemonize::new()
        .pid_file(&pid_file)
        .working_directory(utx_root);

    if let Err(e) = daemon.start() {
        match e {
            daemonize::DaemonizeError::LockPidfile(_) => {
                eprintln!("已经有其他进程正在运行");
                error!("启动失败:已经有其他进程正在运行");
                std::process::exit(-1);
            }
            e => {
                return Err(Error::with_chain(e, "daemonize()失败"));
            }
        }
    }

    Ok(())
}

pub fn load_config(
    pp: &ProgParam,
    load_fccs: bool,
    load_dccs: bool,
    load_tccs: bool,
) -> TxConfig {
    let config = match TxConfig::new(&pp.config_file, load_fccs, load_dccs, load_tccs) {
        Ok(c) => c,
        Err(e) => {
            println!("loading configuration error:{:?}", e);
            std::process::exit(-1);
        }
    };
    config
}

fn usage(prog_name: &str) {
    println!("usage:{} [-r utx_root] [-f config_file] [-d]", prog_name);
    println!("\t -r utx_root            specify utx root path");
    println!("\t -f config_file         specify a configuration file, default to $utx_root/etc/tx.json");
    println!("\t -d                     run as a daemon");
    println!("");
}

pub fn parse_args() -> ProgParam {

    let mut args = env::args();
    let mut prog_name = args.next().unwrap();
    let mut utx_root = String::new();
    let mut config_file = String::new();
    let mut daemonize = false;
    let pos = match prog_name.rfind('/') {
        Some(pos) => pos+1,
        None => 0,
    };
    prog_name = prog_name.split_at(pos).1.to_string();

    loop {
        match args.next() {
            None => {
                break;
            }
            Some(arg) => match arg.as_str() {
                "-v" => {
                    println!("{} version {}", prog_name, crate::version::VERSION);
                    println!("{} build time: {}", prog_name, crate::version::BUILD_TIME);
                    std::process::exit(0);
                }
                "-f" => {
                    if let Some(val) = args.next() {
                        config_file = val;
                    } else {
                        eprintln!("invalid parameter");
                        usage(&prog_name);
                        std::process::exit(-1);
                    }
                }
                "-r" => {
                    if let Some(val) = args.next() {
                        utx_root = val;
                    } else {
                        eprintln!("invalid parameter");
                        usage(&prog_name);
                        std::process::exit(-1);
                    }
                 }
                "-d" => {
                    daemonize = true;
                }
                _ => {
                    eprintln!("invalid parameters");
                    usage(&prog_name);
                    std::process::exit(-1);
                }
            },
        }
    }

    if utx_root.is_empty() {
        utx_root = match env_utx_root() {
            Some(val) => val,
            None => {
                eprintln!("please specify utx_root by '-r path', or by set UTX_ROOT or HOME environment variable");
                std::process::exit(-1);
            }
        };
    }

    if config_file.is_empty() {
        config_file = format!("{}/utx/etc/tx.json",utx_root);
    }

    let pp = ProgParam {
        utx_root: utx_root,
        prog_name: prog_name,
        config_file:  config_file,
        daemonize: daemonize,
    };

    pp
}

//pub fn ensure_file(path_file: &str) -> Result<File> {
pub fn ensure_file(path_file: &str, millis: Option<u64>) -> Result<File> {
    match std::fs::File::create(path_file) {
        Ok(f) => return Ok(f),
        Err(_e) => {
            ensure_path(path_file)?;
            //sleep(millis)可以让fpull能够及时捕捉新创建的目录
            millis.map(|m| thread::sleep(time::Duration::from_millis(m)));
        }
    }

    Ok(std::fs::File::create(path_file)?)
}

pub fn ensure_path(path_file: &str) -> Result<()> {
    let pos = path_file.rfind('/').unwrap_or(path_file.len()-1);
    let (path, _file) = path_file.split_at(pos);
    std::fs::create_dir_all(path).
        chain_err(||format!("ensure_path()创建目录{}失败",path))?;
    Ok(())
}

    fn sperm(st_mode: u32) -> String {
        let mut buf = String::from("");

        buf.push(if 0 != st_mode & libc::S_IFDIR { 'd' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IRUSR { 'r' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IWUSR { 'w' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IXUSR { 'x' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IRGRP { 'r' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IWGRP { 'w' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IXGRP { 'x' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IROTH { 'r' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IWOTH { 'w' } else { '-' });
        buf.push(if 0 != st_mode & libc::S_IXOTH { 'x' } else { '-' });
        return buf;
    }

const MONTHS: [&'static str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

pub fn get_file_info(file: &str, info: &mut String) {
    let mut s: libc::stat = unsafe { mem::zeroed() };
    let path = CString::new(file).unwrap();
    let ret = unsafe { libc::stat(path.as_ptr(), &mut s) };
    if ret != 0 {
        info.push_str(&format!("{}\r\n", file));
    }

    let tm: *mut libc::tm = unsafe { libc::localtime(&s.st_mtime) };
    let to_skip = match file.rfind('/') {
        Some(pos) => pos + 1,
            None => 0,
    };
    let name: String = file.chars().skip(to_skip).collect();

    unsafe {
        info.push_str(
            &format!(
                "{:10} {:>4} {:>4} {:>8} {:>12} {:>4} {:02} {:02}:{:02} {:<}\r\n",
                sperm(s.st_mode),
                s.st_nlink,
                s.st_uid,
                s.st_gid,
                s.st_size,
                MONTHS[(*tm).tm_mon as usize % 12],
                (*tm).tm_mday,
                (*tm).tm_hour,
                (*tm).tm_min,
                name
               )
        );
    }
}

pub fn backup_file(root_path: &str, rel_file: &str, backup_subpath: &str) -> Result<()> {

    let pos = rel_file.rfind('/').unwrap_or(0);
    let (sub_dir, file) = rel_file.split_at(pos);

    let backup_path = match sub_dir.len() {
        0 => format!("{}/{}", root_path, backup_subpath),
        _ => format!("{}/{}/{}", root_path, backup_subpath, sub_dir),
    };
    std::fs::create_dir_all(&backup_path)
        .chain_err(||format!("backup_file()创建目录{}失败",backup_path))?;
    let backup_path_file = format!("{}/{}", backup_path, file);

    let path_file = format!("{}/{}", root_path, rel_file);
    std::fs::rename(&path_file, &backup_path_file)
        .chain_err(||format!("backup_file()移动文件{}到{}失败",path_file,backup_path_file))?;
    Ok(())
}

pub fn data_available(fd: c_int) -> bool {
    let mut bytes:c_int = 0;
    let pointer = &mut bytes as *mut _ as *mut c_void;
    let r = unsafe { libc::ioctl(fd, libc::FIONREAD, pointer) };
    r == 0 &&  bytes > 0
}

pub fn set_so_rcvbufforce(socket_fd: RawFd, rcv_buf_size:u32) -> bool
{
    0 == unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &rcv_buf_size as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    }
}

pub fn set_so_sndbufforce(socket_fd: RawFd, snd_buf_size:u32) -> bool
{
    0 == unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUFFORCE,
            &snd_buf_size as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    }
}

pub fn create_bound_tcp_stream(bind_interface: &String, peer_addr: &String) -> Result<std::net::TcpStream> {
    let sockaddr: std::net::SocketAddr = peer_addr.parse()
        .chain_err(||ErrorKind::UnrecoverableError(line!(),
        format!("网络地址'{}'格式非法", peer_addr)))?;
    let domain = match sockaddr.is_ipv4() {
        true => Domain::ipv4(),
        false => Domain::ipv6(),
    };

    let socket = Socket::new(domain, Type::stream(), None).chain_err(||"Socket::new() failed")?;
    if bind_interface.len() != 0 {
        let mut c_interface = bind_interface.clone();
        c_interface.push('\0');
        let fd = socket.as_raw_fd();
        match unsafe { bind_socket_to_interface(fd, c_interface.as_ptr()) } {
            0 => {},
            _ => {
                error!("bind_socket_to_interface('{}') failed.", bind_interface);
                return None.ok_or(
                    ErrorKind::UnrecoverableError(line!(),format!("绑定网卡'{}'失败",bind_interface)))?;
            },
        }
    }

    socket
        .connect(&socket2::SockAddr::from(sockaddr))
        .chain_err(||ErrorKind::RecoverableError(line!(), format!("连接'{}'失败",peer_addr)))?;
    let tcp_stream = socket.into_tcp_stream();
    tcp_stream.set_nodelay(true)?;
    //tcp_stream.set_nonblocking(false)?;
    /*
    tcp_stream
        .set_read_timeout(Some(std::time::Duration::new(30,0))) //设置读超时时间30秒
        .chain_err(||ErrorKind::RecoverableError(line!(), "set_read_timeout(30) failed".to_string()))?;
    */

    Ok(tcp_stream)
}

pub fn normalized_path(path: &str) -> String {
    let mut v:Vec<char> = path.trim_end_matches('/').chars().collect();
    v.dedup_by(|a,b| *a=='/' && *b=='/');
    v.into_iter().collect::<String>()
}

