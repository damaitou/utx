
use mylib::util;
use mylib::ftp;
use mylib::config::ChannelMode;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::net::{SocketAddr, TcpStream};
use std::io::{self, Read, Write};
use socket2::{Socket, Domain, Type};
use log::{error, warn, info};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use ssh2::{self, Session};
use ringbuf::*;

#[macro_use]
extern crate lazy_static;

#[allow(dead_code)]
fn test_ftp()
{
    let pp = util::parse_args();
    let config = util::load_config(&pp, true, false, false);

    let fcc = config.get_fcc(2).expect("fcc 2 not found");
    let cs = match &fcc.mode {
        ChannelMode::ClientPull(cs) => cs,
        _ => {
            eprintln!("invalid client_setting");
            return;
        }
    };

    println!("\r={}, \n={}", b'\r', b'\n');
    println!("cs.crypto={}", cs.crypto);

    let mut ftp = ftp::FtpStream::new(
        0,
        fcc.channel,
        fcc.vchannel,
        false,
        &fcc,
        &cs,
        "test",
        false,
    ).expect("create FtpStream failed");

    for _i in 0..2 {
        let vs = ftp.ftp_list("//")
            .map_err(|e| {eprintln!("error: {}",e); e})
            .expect("ftp_list failed");
        for v in vs {
            println!("{} => '{}' (raw: {})", v.0, v.1, v.2);
        }
        println!("ftp_list ok {}, sleep 2 seconds...", _i);
        thread::sleep(Duration::from_secs(2));
    }

    let now = Instant::now();
    let is_ok  = ftp.ftp_fetch_file("大家好//测试文件aa.txt", &None, &mut None)
        .map_err(|e| {eprintln!("error: {}",e); e})
        .expect("fetch file failed");
    println!("elapsed={},is_ok={}", now.elapsed().as_millis(), is_ok);

    let now = Instant::now();
    let is_ok  = ftp.ftp_fetch_file("大家好//测试文件.txt", &None, &mut None)
        .map_err(|e| {eprintln!("error: {}",e); e})
        .expect("fetch file failed");
    println!("elapsed={},is_ok={}", now.elapsed().as_millis(), is_ok);
    /*
    let now = Instant::now();
    ftp.ftp_put_file("percona.zip", None).expect("put percona.zip failed");
    println!("{}", now.elapsed().as_millis());
    */
}

#[allow(dead_code)]
fn socket2_listener(sockaddr: SocketAddr, backlog: i32) -> io::Result<Socket> {
    let domain = match sockaddr.is_ipv4() {
        true => Domain::ipv4(),
        false => Domain::ipv6(),
    };
    let socket = Socket::new(domain, Type::stream(), None)?;
    socket.set_reuse_address(true)?;
    socket.bind(&socket2::SockAddr::from(sockaddr))?;
    socket.listen(backlog)?;
    Ok(socket)
}

#[allow(dead_code)]
fn test_socket2_listener() 
{
    let bind_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    println!("marker.............begin");
    let listener = socket2_listener(bind_addr, 1).unwrap();
    let async_listener = async_std::net::TcpListener::from(listener.into_tcp_listener());
    println!("marker.............end");
}

#[allow(dead_code)]
fn test_socket2_client() ->io::Result<Socket>
{
    let socket = Socket::new(Domain::ipv4(), Type::stream(), None)?;
    let size = socket.recv_buffer_size()?;
    println!("recv_buffer_size={}", size);

    //socket.set_recv_buffer_size(1024*300)?;
    set_so_rcvbufforce(socket.as_raw_fd(), 1024*300);
    let size = socket.recv_buffer_size()?;
    println!("recv_buffer_size={}", size);
    Ok(socket)
}

#[allow(dead_code)]
fn set_so_rcvbufforce(socket_fd: RawFd, rcv_buf_size:i32)
{
    //let rcv_buf_size:i32 = 1024*300;
    let ret = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET, 
            libc::SO_RCVBUFFORCE, 
            &rcv_buf_size as *const _ as *const libc::c_void, 
            std::mem::size_of::<i32>() as u32,
        )
    };
    if ret!=0 {
        eprintln!("setsockopt failed");
    }
}

fn set_so_sndbufforce(socket_fd: RawFd, snd_buf_size:i32)
{
    let snd_buf_size:i32 = 1024*300;
    let ret = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET, 
            libc::SO_SNDBUFFORCE, 
            &snd_buf_size as *const _ as *const libc::c_void, 
            std::mem::size_of::<i32>() as u32,
        )
    };
    if ret!=0 {
        eprintln!("setsockopt failed");
    }
}

#[allow(dead_code)]
fn test_ringbuf()
{
    let rb = RingBuffer::<std::string::String>::new(100);
    let (mut producer, mut consumer) = rb.split();

    let pjh = thread::spawn(move || {
        println!("producer born");
        for _i in 0..1000 {
            if producer.is_full() {
                thread::sleep(Duration::from_millis(1));
            }
            else {
                producer.push(format!("hello {}",_i)).expect("producer push failed");
            }
        }
        println!("producer exit");
    });

    let cjh = thread::spawn(move || {
        println!("consumer born");
        for _i in 0..1000 {
            if consumer.is_empty() {
                thread::sleep(Duration::from_millis(1));
            }
            else {
                let msg = consumer.pop().expect("consumer pop() failed");
                println!("msg {}:", msg);
            }
        }
        println!("consumer exit");
    });

    pjh.join().unwrap();
    cjh.join().unwrap();
}

fn test_sftp() {
    let tcp = TcpStream::connect("127.0.0.1:22").unwrap();
    let mut sess = Session::new().unwrap();
    sess.set_tcp_stream(tcp);
    sess.handshake().unwrap();
    sess.userauth_password("damaitou", "hello").unwrap();
    assert!(sess.authenticated());

    let sftp_lister = sess.sftp().unwrap();
    let (tx,rx) = std::sync::mpsc::channel::<(PathBuf,bool)>();

    let sftp_reader = sess.sftp().unwrap();
    let _handler = thread::spawn(move|| {
        let mut buf = [0u8; 10];
        loop {
            let (path, next) = rx.recv().unwrap();
            println!("file={:?}", &path);
            if !next {
                println!("quitting...");
                break;
            }

            let mut file = sftp_reader.open(&path).unwrap();
            file.read(&mut buf).unwrap();
            file.close();
            println!("content={}", String::from_utf8_lossy(&buf));
        }
    });

    let dirs = sftp_lister.readdir(Path::new("dev/rust/utx/src/binprog")).unwrap();
    for (path,stat) in dirs {
        if stat.is_file() {
            println!("sending:{:?}", &path);
            tx.send((path,true));
        }
    }
    tx.send((PathBuf::new(), false)); //signal to quit

    _handler.join();
}

/*
fn test_lazy_static() {
    let num1:u32 = 100;
    let cb = || {
        num1+1
    };
    lazy_static! {
        //static ref NUM: u32  = || { num1+1 };
        //static ref NUM: u32  = cb();
    }
}
*/

fn main()
{
    //test_ftp();
    //test_socket2_listener();
    //test_socket2_client();
    //test_ringbuf();
    test_sftp();
}

