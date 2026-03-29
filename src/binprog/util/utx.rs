
use std::io::Error;
use std::io::ErrorKind;
use std::os::raw::{c_void, c_int, c_char};
use std::os::unix::io::{RawFd,AsRawFd};
use log::{error, trace};

pub const BLOC_SIZE : u32 = 819200;

/*
pub const UTX_TYPE_SYS: u8 = 0;
pub const UTX_TYPE_DATAGRAM: u8 = 1;
pub const UTX_TYPE_BLOCK: u8 = 2;
pub const UTX_TYPE_FILE: u8 = 3;

pub const UTX_OPT_STREAM: u8 = 0;
pub const UTX_OPT_DATAGRAM: u8 = 1;

pub const BTX_TYPE_TCP_T2R: u8 = 10;
pub const BTX_TYPE_TCP_R2T: u8 = 11;
*/
pub const UTX_TYPE_TCP_T2R: u8 = 10;
pub const UTX_TYPE_TCP_R2T: u8 = 11;

#[link(name = "utx", kind = "static")]
extern "C" {
    fn strerror(errnum: i32) -> *const c_char;
    fn utx_set_tx_mtu(mtu: u32) -> u32;
    fn utx_init_sender(
        tx_mac: *const u8, 
        rx_mac: *const u8,
        bloc_size: u32,
    ) -> u64;
    fn utx_drop_sender(handle: u64);
    fn utx_send_a_file(
        handle: u64,
        channel: i32,
        root_path: *const u8,
        file: *const u8,
        fsize: *mut u64,
        errno: *mut i32,
    ) -> i32;
    fn utx_send_bloc_header(
        handle: u64,
        channel: i32,
        path: *const u8,
        filename: *const u8,
    ) -> i32;
    fn utx_send_datagram(
        handle: u64,
        channel: i32,
        buf: *const u8,
        len: u32) -> i32;
    fn utx_send_bloc_buf(
        handle: u64,
        channel: i32,
        buf: *const u8,
        len: u32,
        header_bit: i32,
        packet_opt: i32,
    ) -> i32;
    fn btx_send_tcp_buf(
        handle:u64,
        channel:i32,
        session_id:u16,
        btx_type:u8,
        head_bit:c_int,
        tail_bit:c_int,
        this_seq: *mut u16,
        buf:*const u8,
        len:u32
    ) -> i32;

    fn utx_set_rx_mtu(mtu: u32) -> u32;
    fn utx_set_rx_buffer_size_mb(mb: u32) -> u32;
    fn utx_init_receiver(
        rx_mac: *const u8,
        utx_handler: ::std::option::Option<
            unsafe extern "C" fn(
                token: *mut c_void,
                utx_type: u8,
                channel: u8,
                seq: u16,
                head: u8,
                tail: u8,
                check: u16,
                session_id: u16,
                packet_opt: u8,
                packet_head: u8,
                packet_tail: u8,
                payload: *mut u8,
                payload_size: u16,
            ),
        >,
    ) -> u64;

    pub fn utx_receiver_get_socket_fd(handle: u64) -> i32;
    pub fn utx_receiver_loop(handle: u64, fd: c_int, token: *mut c_void) -> i32;
    pub fn utx_receiver_loop_on_available_packets(handle: u64, token: *mut c_void) -> i32;
}

pub struct UtxReceiver {
    handle: u64,
}
impl AsRawFd for UtxReceiver {
    fn as_raw_fd(&self) -> RawFd {
        unsafe { utx_receiver_get_socket_fd(self.handle) }
    }
}
impl UtxReceiver {
    pub fn set_rx_mtu(mtu: u32) {
        unsafe {
            utx_set_rx_mtu(mtu);
        }
    }

    pub fn set_rx_buffer_size_mb(mb: u32) {
        unsafe {
            utx_set_rx_buffer_size_mb(mb);
        }
    }

    pub fn new(
        rx_mac: &str,
        utx_handler: ::std::option::Option<
            unsafe extern "C" fn(
                token: *mut c_void,
                utx_type: u8,
                channel: u8,
                seq: u16,
                head: u8,
                tail: u8,
                check: u16,
                session_id: u16,
                packet_opt: u8,
                packet_head: u8,
                packet_tail: u8,
                payload: *mut u8,
                payload_size: u16,
            )>,
    ) -> Option<UtxReceiver> {
        unsafe {
            let mut c_rx_mac = rx_mac.to_string();
            c_rx_mac.push('\0');
            let h = utx_init_receiver( c_rx_mac.as_ptr(), utx_handler);
            match h {
                0 => None,
                h => Some(UtxReceiver {handle: h}),
            }
        }
    }

    /*
    pub fn get_socket_fd(&self) ->i32 {
        unsafe {
            utx_receiver_get_socket_fd(self.handle)
        }
    }
    */

    pub fn run(&self, notify_read_fd: i32, token: *mut c_void) {
        unsafe {
            utx_receiver_loop(self.handle, notify_read_fd, token);
        }
    }

    pub fn loop_on_available_packets(&self, token: *mut c_void) {
        unsafe {
            utx_receiver_loop_on_available_packets(self.handle, token);
        }
    }
}

pub struct UtxSender {
    handle: u64,
}
impl Drop for UtxSender {
    fn drop(&mut self) {
        if !self.handle != 0 {
            unsafe {
                trace!("dropping UtxSender...");
                utx_drop_sender(self.handle);
            }
        }
    }
}
impl UtxSender {
    pub fn set_tx_mtu(mtu: u32) {
        unsafe {
            utx_set_tx_mtu(mtu);
        }
    }

    pub fn new(tx_mac: &str, rx_mac: &str) -> Option<UtxSender> {
        unsafe {
            let mut c_tx_mac = tx_mac.to_string();
            let mut c_rx_mac = rx_mac.to_string();
            c_tx_mac.push('\0');
            c_rx_mac.push('\0');
            let handle: u64 = utx_init_sender(c_tx_mac.as_ptr(), c_rx_mac.as_ptr(), BLOC_SIZE);
            if handle == 0 {
                return None;
            }

            let ufs = UtxSender { handle: handle };
            return Some(ufs);
        }
    }

    pub fn send_a_file(&self, channel: usize, path: &str, file: &str) -> Result<u64, Error> {
        let mut c_path: String = path.to_string();
        let mut c_file: String = file.to_string();
        c_path.push('\0');
        c_file.push('\0');

        unsafe {
            let mut fsize = 0;
            let mut errno = 0;
            let r = utx_send_a_file(
                self.handle,
                channel as i32,
                c_path.as_ptr(),
                c_file.as_ptr(),
                &mut fsize,
                &mut errno,
            );

            return match r {
                0 => Ok(fsize),
                _ => {
                    let ptr = strerror(errno);
                    let cstr = std::ffi::CStr::from_ptr(ptr);
                    let msg = format!("UtxSender发送文件'{}/{}'失败, error:{:?}", path, file, cstr);
                    error!("{}", &msg);
                    Err(Error::new(ErrorKind::Other, msg))
                }
            };
        }
    }

    pub fn send_bloc_header(&self, channel: usize, path: &str, file: &str) -> bool {
        let sent = unsafe {
            let mut c_path = path.to_string();
            let mut c_file = file.to_string();
            c_path.push('\0');
            c_file.push('\0');
            utx_send_bloc_header(
                self.handle,
                channel as i32,
                c_path.as_ptr(),
                c_file.as_ptr(),
            )
        };
        sent > 0
    }

    pub fn send_datagram(&self, channel: usize, buf: &[u8]) -> bool {
        let sent = unsafe {
            utx_send_datagram(
                self.handle,
                channel as i32,
                buf.as_ptr(),
                buf.len() as u32,
            )
        };

        sent == 0
    }

    pub fn send_bloc_buf(&self, channel: usize, buf: &[u8], head_bit: bool, packet_opt: i32) -> bool {
        let sent = unsafe {
            utx_send_bloc_buf(
                self.handle,
                channel as i32,
                buf.as_ptr(),
                buf.len() as u32,
                if head_bit { 1 } else { 0 },
                packet_opt,
            )
        };

        sent == buf.len() as i32
    }

    pub fn tcp_connect(&self, channel: usize, session_id: u16, this_seq: &mut u16, buf:Option<&[u8]>) -> bool {
        let tmp:u8 = 0;
        let (buf_ptr, buf_len) = match buf {
            Some(buf) => (buf.as_ptr(), buf.len() as u32),
            None => (&tmp as *const u8, 0),
        };
        let ret = unsafe {
            btx_send_tcp_buf(
                self.handle, 
                channel as i32, 
                session_id, 
                UTX_TYPE_TCP_T2R, 
                1,                      //head_bit 1 to connect
                0,                      //tail_bit
                this_seq as *mut _,
                buf_ptr,
                buf_len,
            )
        };
        ret == 0
    }

    /*
    pub fn tcp_connect_resp(&self, channel: usize, session_id: u16, this_seq: &mut u16, success: bool) -> bool {
        let tmp:u8 = 0;
        let ret = unsafe {
            btx_send_tcp_buf(
                self.handle, 
                channel as i32, 
                session_id, 
                BTX_TYPE_TCP_R2T, 
                if success { 1 } else { 0 },    //head_bit
                0,                              //tail_bit
                this_seq as *mut _,
                &tmp as *const u8,
                0,
            )
        };
        ret == 0
    }
    */

    pub fn tcp_disconnect(&self, channel: usize, session_id: u16, this_seq: &mut u16, btx_type: u8) -> bool {
        let tmp:u8 = 0;
        let ret = unsafe {
            btx_send_tcp_buf(
                self.handle, 
                channel as i32, 
                session_id, 
                btx_type, 
                0,                              //head_bit
                1,                              //tail_bit 1 to disconnect
                this_seq as *mut _,
                &tmp as *const u8,
                0,
            )
        };
        ret == 0
    }

    pub fn tcp_send_data(&self, channel: usize, session_id: u16, this_seq: &mut u16, btx_type: u8, buf: &[u8]) -> bool {
        let ret = unsafe {
            btx_send_tcp_buf(
                self.handle, 
                channel as i32, 
                session_id, 
                btx_type, 
                0,                      //head_bit
                0,                      //tail_bit
                this_seq as *mut _,
                buf.as_ptr(),
                buf.len() as u32,
            )
        };
        ret == 0
    }

    /*
    pub fn send_sys_buf(&self, channel: usize, buf: &[u8], head_bit: bool) -> bool {
        let sent = unsafe {
            utx_send_buf(
                self.handle,
                channel as i32,
                buf.as_ptr(),
                buf.len() as u32,
                UTX_TYPE_SYS,
                if head_bit { 1 } else { 0 },
            )
        };

        sent == buf.len() as i32
    }
    */
}
