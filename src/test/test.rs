
extern crate radix_trie;
extern crate md5;
extern crate des;
use std::collections::VecDeque;
use std::thread;
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use std::os::unix::net::{UnixStream};
use std::net::TcpStream;
use std::io::{Read, Write};
use std::os::raw::c_int;
use std::os::unix::io::AsRawFd;
use rand_core::RngCore;
use rand::Rng;

use mylib::ftp;
use mylib::config;
use mylib::errors::*;
use mylib::virus::VirusScanner;
use mylib::license::License;
const CLAMD_SOCK_FILE: &'static str = "/var/run/clamd.scan/clamd.sock";

#[link(name = "utx", kind = "static")]
extern "C" {
    fn bind_socket_to_interface(
        s: c_int,
        if_name: *const u8, 
    ) -> c_int;
}

fn socket_test1() {
    let mut tcp_stream = TcpStream::connect("192.168.100.202:9091").unwrap();
    let fd = tcp_stream.as_raw_fd();
    let r = unsafe { bind_socket_to_interface(fd, "ens33\0".as_ptr()) };
    //let r = unsafe { bind_socket_to_interface(fd, "ens37\0".as_ptr()) };
    println!("r={}", r);

    tcp_stream.write("USER abc\r\n".as_bytes()).unwrap();
    let mut buf = [0 as u8; 1024];
    let size = tcp_stream.read(&mut buf).unwrap();
    println!("buf={}", String::from_utf8_lossy(&buf[0..size]));
}

fn des_test1() {
    let input = "hello-world,离离原上草，一岁一枯荣，野火烧不尽，春风吹又生.";
    //let encoded = License::encode_license(input, "bkeybkey");
    let encoded = License::encode_string(input).expect("encode failed!");
    println!("encoded={}", encoded);
    //let decoded = License::decode_license(&encoded, "bkeybkey").expect("decode failed!");
    let decoded = License::decode_string(&encoded).expect("decode failed!");
    println!("decoded={},decoded.len={},input.len={}", decoded, decoded.len(), input.len());
}

fn clamd_test2() -> Result<()>
{
    let mut scanner = VirusScanner::new(CLAMD_SOCK_FILE);
    for _i in 0..10 {
        let (novirus, result) = scanner.scan("/root/utx/log/ftpd_r00024.log")?;
        eprintln!("novirus={}, result={}", novirus, result);
        let (novirus, result) = scanner.scan("/root/mlt/rust/utx/virus_sample/3558_virus_sample.zip")?;
        eprintln!("novirus={}, result={}", novirus, result);
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

fn clamd_test() -> Result<()>
{
    let sock_file = "/var/run/clamd.scan/clamd.sock";
    let mut stream = UnixStream::connect(sock_file)?;

    let mut buf = [0 as u8; 1024];

    //let cmd = "zPING\0".to_string();
    let cmd = "zIDSESSION\0zPING\0".to_string();
    stream.write(cmd.as_bytes())?;

    let size = stream.read(&mut buf)?;
    eprintln!("response:{}",String::from_utf8_lossy(&buf[..size]));

    for _i in 0..10 {
        let cmd = "zSCAN /root/mlt/rust/utx/virus_sample/3558_virus_sample.zip\0".to_string();
        stream.write(cmd.as_bytes())?;
        let size = stream.read(&mut buf)?;
        eprintln!("size:{}, response:'{}'", size, String::from_utf8_lossy(&buf[..size]));
    }

    Ok(())
}

fn q_test()
{
    let q: Arc<Mutex<VecDeque<i32>>> = Arc::new(Mutex::new(VecDeque::new()));
    let thread_q = q.clone();

    let handle = thread::spawn(move||{
        let mut counter = 0;
        loop {
            let mut q = thread_q.lock().unwrap();
            match q.pop_front() {
                Some(val) => {
                    eprintln!("val={}", val);
                    counter += 1;
                    if counter >= 100 {
                        break;
                    }
                }
                None => {
                    drop(q);
                    //thread::sleep(Duration::from_millis(10));
                }
            }
        }
    });

    for i in 0..100 {
        {
            q.lock().unwrap().push_back(i);
            eprintln!("{} sent.", i);
        }
        //thread::sleep(Duration::from_millis(10));
    }

    handle.join().unwrap();
    eprintln!("q_est() done");
}

fn ft2()
{
    let s = format!("{}{}{}{}{}", "abcd", '\0', "1234", '\0', "xyz");
    //let s = format!("{}\0{}\0{}", "abcd", "1234", "xyz");
    println!("{}.len()={}",s, s.len());

    let v : Vec<&str> = s.split('\0').collect();
    for e in v {
        println!("e={}", e);
    }
}

fn ft1()
{
    //let f = std::fs::File::open("/root/mlt/rust/utx/1").unwrap();
    let s = std::fs::read_to_string("/root/mlt/rust/utx/1").unwrap();
    println!("s.len={}", s.len());
    /*
    for c in s.as_bytes() {
        println!("\tc={}", c);
    }
    */
    let mut ctx = md5::Context::new();
    ctx.consume(s.as_bytes());
    let d = ctx.compute();
    println!("md5='{:x}'", d);
}

fn md5_t2()
{
    let mut buf = [0 as u8; 2024];
    rand::thread_rng().fill_bytes(&mut buf);
    let mut ctx = md5::Context::new();
    let start_ts = Instant::now();
    for _i in 0..1000 {
        ctx.consume(&buf[..]);
    }
    let d = ctx.compute();
    let used_time = start_ts.elapsed().as_millis();
    println!("md5='{:x}', used_time={}", d, used_time);
}

fn md5_t1()
{
    let mut ctx = md5::Context::new();
    ctx.consume("abcdxyz\0");
    //ctx.consume("xyz");
    let d = ctx.compute();
    println!("md5='{:x}'", d);
}

fn radix_trie_test()
{
    let mut tree = radix_trie::Trie::new();
    tree.insert("abcdefg", 1);
    tree.insert("他妈的", 2);

    let a = tree.get("abcdefg").unwrap_or(&-1);
    let b = tree.get("他妈的").unwrap_or(&-1);

    let a1 = tree.get_ancestor("abcde").is_some();
    let a2 = tree.get_ancestor("wabcdefg").is_some();

    println!("a={},b={}", a,b);
    println!("a1={},a2={}", a1,a2);
}

fn main()
{
    socket_test1();
    des_test1();
    md5_t2();

    /*
    if let Err(e) = clamd_test2() {
        eprintln!("error:{:?}", e);
    }
    */
    return;

    q_test();
    ft2();
    ft1();
    md5_t1();
    let len = 123;
    let len_buf = format!("{:05}", len);
    println!("{}", len_buf);
    println!("{}", len_buf.len());

    let val = encode(3,4);
    println!("val={}", val);

    let (a,b) = decode(val);
    println!("a={},b={}", a, b);

    //radix_trie_test();
    /*
    let cs = config::ClientSetting {
        remote_ftp_host_address: "127.0.0.1:9091".to_string(),
        remote_ftp_user: "a3".to_string(),
        remote_ftp_password: "a3".to_string(),
        remote_ftp_root_path: "/".to_string(),
        local_root_path: "/tmp/tx2".to_string(),
        threads_number: 2,
    };

    let mut stream = match ftp::FtpStream::new(0, &cs, "testr") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} connect to ftp_server failed:{:?}", "tester", e);
            return;
        }
    };

    stream.ftp_mkdir("/a1").unwrap();
    if let Err(e) = stream.ftp_put_file("/a1/big", Some("BLOC")) {
        println!("error:{:?}", e);
    }
    */
}

fn encode(action:u32, channel:u32) ->u64
{
    println!("{},{},{}", action, action as u64, (action as u64) << 32);
    ((action as u64) << 32) + (channel as u64)
}

fn decode(flag:u64) -> (u32, u32) {
    let channel:u32 = flag as u32;
    let action:u32 = (flag >> 32) as u32;
    (action, channel)
}

