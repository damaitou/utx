
use std::net::{SocketAddr};

pub const MAX_ENCRYPTED_BLOCK_SIZE:usize = 10*1024*1024;

pub const FTP_FILE: u8 = 0;
pub const FTP_DIR:  u8 = 1;
pub const FTP_BLOC: u8 = 2;
pub const FTP_NONE: u8 = 99;

use crate::errors::*;
use crate::config::{WordChecker};
use crate::virus;

pub struct CallBackOnListedFile<'a> {
    pub callback: &'a dyn Fn(&str, u8) -> Result<()>,
}

pub trait FileTransfer {
    fn fetch_dir(&mut self, rel_path: &str, cbof: &CallBackOnListedFile, depth: u32, truncate_empty_directory:bool) -> Result<()>;
    fn put_dir(&mut self, rel_path: &str, cbof: &CallBackOnListedFile, depth: u32, truncate_empty_directory:bool) -> Result<()>;
    fn rm_dir(&mut self, rel_dir: &str) -> Result<bool>;

    fn fetch_file(&mut self, rel_file: &str, wc: &Option<WordChecker>, scanner: &mut Option<virus::VirusScanner>) -> Result<bool>;
    fn put_file(&mut self, rel_file: &str) -> Result<()>;
    fn rm_file(&mut self, rel_file: &str) -> Result<bool>;
    fn rm_local_file(&mut self, rel_file: &str) -> Result<()>;

    fn noop(&mut self) -> Result<bool>;
    fn peer_addr(&self) -> SocketAddr;
}

