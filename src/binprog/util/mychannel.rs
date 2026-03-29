
use std::io::{Result, Error, ErrorKind};
use std::os::unix::io::{RawFd,AsRawFd};
use std::os::raw::c_int;
extern "C" {
    pub fn pipe(pipefd: *const c_int) -> c_int;
    pub fn write(fd: c_int, buf: *const u8, count: usize) -> isize;
    pub fn read(fd: c_int, buf: *mut u8, count: usize) -> isize;
}

#[derive(Clone)]
pub struct MySender {
    write_fd: i32,
}

impl MySender {
    pub fn send_object<T>(&self, obj: T) -> Result<()> {
        let obj_raw = Box::into_raw(Box::new(obj)) as u64;
        let buf  = unsafe { std::slice::from_raw_parts(&obj_raw as *const _ as *const u8, 8) };
        let n = unsafe { write(self.write_fd, buf.as_ptr(), 8) };
        if n == 8 {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "write object failed."))
        }
    }
}

pub struct MyReceiver {
    read_fd: i32,
}

impl MyReceiver {
    pub fn recv_object<T>(&self) -> Result<T> {
        let mut obj_raw: u64 = 0;
        let buf = unsafe { std::slice::from_raw_parts_mut(&mut packet as *mut _ as *mut u8, 8) };
        let mut n_recv:isize = 0;
        while n_recv < 8 {
            match  unsafe { read(self.read_fd, buf.as_mut_ptr(), (8-n_recv) as usize) } {
                0 => break,
                n => n_recv += n,
            }
        }

        if n_recv == 8 && obj_raw != 0 {
            let obj = unsafe {Box::from_raw(obj_raw as *mut T)};
            Ok(*obj)
        } else {
            Err(Error::new(ErrorKind::Other, "read object failed."))
        }
    }
}

impl AsRawFd for MyReceiver {
    fn as_raw_fd(&self) -> RawFd {
        self.read_fd
    }
}

pub fn channel() -> Result<(MySender, MyReceiver)> {
    unsafe {
        let pipefd = [0, 0];
        match pipe(pipefd.as_ptr()) {
            0 => {
                Ok((
                    MySender { write_fd: pipefd[1], }, 
                    MyReceiver { read_fd: pipefd[0], }
                ))
            },
            _ => Err(Error::new(ErrorKind::Other, "pipe()失败")),
        }
    }
}

