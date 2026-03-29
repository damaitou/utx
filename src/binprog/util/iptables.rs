
use std::process::Command;
use log::{error, trace};

pub fn iptables_append_dnat(from_host: &str, from_port:u16, to_host: &str, to_port: u16) -> bool {
    trace!("iptables_append_dnat(), from {}:{} to {}:{}", from_host, from_port, to_host, to_port);
    let from_port = format!("{}", from_port);
    let to_port = format!("{}", to_port);
    match Command::new("iptables")
        .env("PATH","/usr/sbin/")
        .args(&[
            "-t","nat",
            "-A", "PREROUTING",
            "-d", from_host, 
            "-p", "tcp", 
            "--dport", &from_port, 
            "-j", "DNAT", 
            "--to-destination", to_host,
            "--to-ports", &to_port,
        ])
        .status()
    {
        Err(e) => {
            error!("iptables_append_dnat() failed, error={:?}", e);
            false
        }
        Ok(val) => val.success()
    }
}

pub fn iptables_delete_dnat(from_host: &str, from_port:u16, to_host: &str, to_port: u16) -> usize {
    trace!("iptables_delete_dnat(), from {}:{} to {}:{}", from_host, from_port, to_host, to_port);
    let from_port = format!("{}", from_port);
    let to_port = format!("{}", to_port);
    let mut count = 0;
    loop {
        match Command::new("iptables")
            .env("PATH","/usr/sbin/")
            .args(&[
                "-t","nat",
                "-D", "PREROUTING",
                "-d", from_host, 
                "-p", "tcp", 
                "--dport", &from_port, 
                "-j", "DNAT", 
                "--to-destination", to_host,
                "--to-ports", &to_port,
            ])
            .status()
            {
                Err(e) => {
                    eprintln!("iptables_delete_dnat() failed, error={:?}", e);
                    break;
                }
                Ok(val) => {
                    if !val.success() { break; } else { count += 1; }
                }
            }
    }
    count
}

/*
pub fn iptables_append_local_redirect(dst_host: &str, dst_port:u16, listening_port:u16) -> bool {
    trace!("iptables_append_local_redirect(), dst_host={}, dst_port={}, listening_port={}", dst_host, dst_port, listening_port);
    let from_port = format!("{}", dst_port);
    let to_port = format!("{}", listening_port);
    match Command::new("iptables")
        .env("PATH","/usr/sbin/")
        .args(&[
            "-t","nat",
            "-A", "PREROUTING",
            "-d", dst_host, 
            "-p", "tcp", 
            "--dport", &from_port, 
            "-j", "REDIRECT", 
            "--to-ports", &to_port,
        ])
        .status()
        {
            Err(e) => {
                error!("iptables_append_local_redirect() failed, error={:?}", e);
                false
            }
            Ok(val) => val.success()
        }
}

pub fn iptables_delete_local_redirect(dst_host: &str, dst_port:u16, listening_port:u16) -> bool {
    trace!("iptables_add_local_redirect(), dst_host={}, dst_port={}, listening_port={}", dst_host, dst_port, listening_port);
    let from_port = format!("{}", dst_port);
    let to_port = format!("{}", listening_port);

    loop {
        match Command::new("iptables")
            .env("PATH","/usr/sbin/")
            .args(&[
                "-t","nat",
                "-D", "PREROUTING",
                "-d", dst_host, 
                "-p", "tcp", 
                "--dport", &from_port, 
                "-j", "REDIRECT", 
                "--to-ports", &to_port,
            ])
            .status()
            {
                Err(e) => {
                    eprintln!("iptables_delete_local_redirect() failed, error={:?}", e);
                    break;
                }
                Ok(val) => if !val.success() { break; },
            }
    }

    true
}
*/

