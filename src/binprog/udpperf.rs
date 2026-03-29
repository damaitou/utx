
use std::net::{Ipv6Addr,IpAddr,SocketAddr,/*UdpSocket*/};
use std::time::{Duration, Instant};
use std::os::unix::io::AsRawFd;

use docopt::Docopt;
use serde::Deserialize;

use mio::net::{UdpSocket};
use mio::*;
use mio_extras::timer;

use mylib::util;

const USAGE: &'static str = "
Usage:
    udpperf -s [options]
    udpperf -c HOST [options]

Options:
    -s, --server            server side.
    -c, --client HOST       client side, HOST to send udp packet.
    -p, --port PORT         UDP port to test performance.
    -b, --bandwidth SPEED   SPEED is Mbps of performance test
    --rwbuf BUFSIZE         RECVBUF_SIZE and SNDBUF_SIZE of udp socket
    --nanos NANOS           sleep nano_seconds after sending each packet
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_server: bool,
    flag_client: Option<String>,
    flag_port: u16,
    flag_bandwidth: Option<u16>,
    flag_rwbuf: Option<u32>,
    flag_nanos: Option<usize>,
}

const UDP_PACKET_SIZE:usize = 32*1024;
struct UdpPacket {
    seq: u64,
    _padding: [u8; UDP_PACKET_SIZE-8],
}

impl UdpPacket {
    fn new() -> UdpPacket {
        UdpPacket {
            seq: 0,
            _padding: [0 as u8; UDP_PACKET_SIZE-8],
        }
    }
}

fn server(args: &Args)
{
    let ipaddr = std::net::IpAddr::V6(<Ipv6Addr>::new(0, 0, 0, 0, 0, 0, 0, 0)); //todo
    let addr = SocketAddr::new(ipaddr, args.flag_port);
    let udp = std::net::UdpSocket::bind(&addr).unwrap_or_else(|e|{
        println!("error:{:?}",e);
        std::process::exit(-1);
    });

    if let Some(rcvbuf_size) = args.flag_rwbuf.as_ref() {
        if !util::set_so_rcvbufforce(udp.as_raw_fd(), *rcvbuf_size) {
            println!("failed to set RCVBUF_SIZE.skipped");
        }
    }

    let mut packet = UdpPacket::new();
    let mut last_seq: u64 = 0;
    let mut traffic: usize = 0;
    let mut packet_lost: usize = 0;
    let mut packet_recv: usize = 0;
    let mut tick = Instant::now();
    loop {
        let mut buf = unsafe { std::slice::from_raw_parts_mut(&mut packet as *mut _ as *mut u8, UDP_PACKET_SIZE) };
        let (n, _peer) = udp.recv_from(&mut buf).unwrap_or_else(|e|{
            println!("recv udp packet error:{:?}", e);
            std::process::exit(-1);
        });

        traffic += n;
        packet_recv += 1;
        if packet.seq == 0 {
            last_seq = 0;
        }
        else {
            if packet.seq>last_seq {
                packet_lost += (packet.seq-last_seq-1) as usize;
            }
            last_seq = packet.seq;
        }

        if tick.elapsed().as_secs() >= 1 {
            println!("recv_packets={}, recv_bytes={}, lost_packets={}, speed={}Mbps", packet_recv, traffic, packet_lost, traffic*8/1024/1024);
            packet_recv = 0;
            packet_lost = 0;
            traffic = 0;
            tick = Instant::now();
        }

    }
}

fn client(args: &Args)
{
    let ipaddr: IpAddr = args.flag_client.as_ref().unwrap().parse().unwrap_or_else(|e|{
        println!("parse ip address error:{:?}", e);
        std::process::exit(-1);
    });
    let peer_addr = SocketAddr::new(ipaddr, args.flag_port);

    let udp = UdpSocket::bind(&"[::]:0".parse::<SocketAddr>().unwrap()).unwrap_or_else(|e|{
        println!("create udp socket failed:{:?}", e);
        std::process::exit(-1);
    });

    if let Some(sndbuf_size) = args.flag_rwbuf.as_ref() {
        if !util::set_so_sndbufforce(udp.as_raw_fd(), *sndbuf_size) {
            println!("failed to set SNDBUF_SIZE.skipped");
        }
    }

    let packets_per_second = args.flag_bandwidth.unwrap() as usize *1024*1024/8 / UDP_PACKET_SIZE;
    let packets_per_10ms = packets_per_second/100;
    let nanosleep_value = match args.flag_nanos {
        Some(nanos) => nanos,
        None => 1000_000_000/packets_per_second/2,
    };
    println!("speed={:?}, packets_per_second={}, packets_per_10ms={}, nano={}", args.flag_bandwidth, packets_per_second, packets_per_10ms, nanosleep_value);

    let mut packet = UdpPacket::new();
    let mut traffic: usize = 0;
    let mut packet_sent: usize = 0;

    let mut secs: usize = 0;
    let mut timer = timer::Timer::default();

    let poll = mio::Poll::new().unwrap_or_else(|e|{
        println!("create Poll failed:{:?}", e);
        std::process::exit(-1);
    });

    poll.register(&timer, Token(0), Ready::readable(), PollOpt::edge()).unwrap_or_else(|e|{
        println!("register timer failed:{:?}", e);
        std::process::exit(-1);
    });

    poll.register(&udp, Token(1), Ready::writable(), PollOpt::level()).unwrap_or_else(|e|{
        println!("register udp failed:{:?}", e);
        std::process::exit(-1);
    });

    let mut events = Events::with_capacity(1024);
    timer.set_timeout(Duration::from_millis(1000), 0);
    loop {
        poll.poll(&mut events, None).expect("poll failed!");
        for _event in events.iter() {
            match _event.token() {
                //timer
                Token(0) => {
                    secs += 1;

                    if secs % 1 == 0 {
                        println!("sent_packets={}, sent_bytes={}, speed={}Mbps", packet_sent, traffic, traffic*8/1024/1024);
                        traffic = 0;
                        packet_sent = 0;
                    }

                    if secs < 10 {
                        timer.set_timeout(Duration::from_millis(1000), 0);
                    } else {
                        std::process::exit(0);
                    }
                }
                //udp writable
                Token(1) => {
                    if packet_sent < packets_per_second {
                        let buf  = unsafe { std::slice::from_raw_parts(&packet as *const _ as *const u8, UDP_PACKET_SIZE) };
                        udp.send_to(&buf, &peer_addr).unwrap_or_else(|e|{
                            println!("send udp packet error:{:?}", e);
                            std::process::exit(-1);
                        });

                        packet_sent += 1;
                        traffic += UDP_PACKET_SIZE;

                        packet.seq += 1;
                        if nanosleep_value != 0 {
                            nanosleep(nanosleep_value);
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

fn main()
{
    let mut args: Args = Docopt::new(USAGE)
            .and_then(|d| Ok(d.help(true)))
            .and_then(|d| d.deserialize())
            .unwrap_or_else(|e| e.exit());
    println!("args={:?}", args);

    if args.flag_bandwidth.is_none() {
        args.flag_bandwidth = Some(10); //10Mbps default
    }

    if args.flag_server {
        server(&args);
    }
    else if args.flag_client.is_some() {
        client(&args);
    }
    else {
        println!("Invalid Arguments");
    }
}

fn nanosleep(nano_secs: usize)
{
    let ts = libc::timespec {
        tv_sec: 0 as libc::time_t,
        tv_nsec: nano_secs as libc::c_long,
    };

    unsafe { libc::nanosleep(&ts as *const _, std::ptr::null_mut()) };
    //unsafe { libc::nanosleep(&ts as *const libc::unix::timespec, std::ptr::null_mut()) };
}


/*
fn duration_to_timespec(duration: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: duration.subsec_nanos() as libc::c_long,
    }
}

pub fn nano_sleep(duration: Duration) -> Option<Duration> {
    let ts = duration_to_timespec(duration);
    let mut remain = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    #[cfg(target_os = "linux")] clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &ts, Some(&mut remain));

    #[cfg(target_os = "macos")] nanosleep(&ts, Some(&mut remain));


    if remain.tv_nsec == 0 && remain.tv_sec == 0 {
        return None;
    }
    Some(timespec_to_duration(remain))
}

*/

