
#![allow(dead_code)]
use std::io::{Read, Write};

pub type Sequence = u8;
pub type FileId = u16;

pub const AGENT_COMES_A_FILE_INFO:  u8 = 1;
pub const AGENT_COMES_A_FILE_DATA:  u8 = 2;
pub const AGENT_COMES_A_FILE_END:   u8 = 3;
//pub const AGENT_COMES_A_FILE_LOST:  u8 = 4; //中途丢包,文件无效
pub const PLEASE_READ: u8 = 10;
pub const PLEASE_WRITE: u8 = 11;

const DATABUF_SIZE: usize = std::mem::size_of::<DataBuf>();

//#[repr(C)]
pub struct Header {
    pub total_len: usize,
    pub header_type: u8,
    pub seq: Sequence,
    pub file_id: FileId,
}

impl Header {
    pub fn new() -> Header {
        Header {
            total_len: 0,
            header_type: 0,
            seq: 0,
            file_id: 0,
        }
    }

    pub fn request_for_read<W: ?Sized>(&mut self, writer: &mut W) -> std::io::Result<()> 
    where W: Write,
    {
        self.header_type = PLEASE_READ;
        self.file_id = 0;
        self.total_len = std::mem::size_of::<Header>();

        let header_buf = unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, self.total_len) };
        writer.write_all(&header_buf)
    }

    pub fn request_for_write<W: ?Sized>(&mut self, writer: &mut W) -> std::io::Result<()> 
    where W: Write,
    {
        self.header_type = PLEASE_WRITE;
        self.file_id = 0;
        self.total_len = std::mem::size_of::<Header>();

        let header_buf = unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, self.total_len) };
        writer.write_all(&header_buf)
    }
}

//#[repr(C)]
pub struct FileInfo {
    pub file_name: [u8;256],
    pub file_name_len: usize,
    pub file_size: usize,
}

impl FileInfo {
    /*
    fn new() -> FileInfo {
        FileInfo {
            file_name: [0; 256],
            file_name_len: 0,
            file_size: 0,
        }
    }
    */
    pub fn set_file_name(&mut self, file_name: &String) {
        let file_name_bytes = file_name.as_bytes();
        self.file_name[0..file_name_bytes.len()].copy_from_slice(file_name_bytes); //todo what is len > 256?
        self.file_name_len = file_name.len();
    }

    pub fn get_file_name(&self) -> String {
        String::from_utf8_lossy(&self.file_name[..self.file_name_len]).to_string()
    }
}

//#[repr(C)]
pub struct DataBuf {
    pub header: Header,
    pub data: [u8; 64*1024-std::mem::size_of::<Header>()],
}

impl DataBuf {
    pub fn new() -> DataBuf {
        DataBuf {
            header: Header::new(),
            data: [0; 64*1024-std::mem::size_of::<Header>()],
        }
    }

    pub fn write_to<W: ?Sized>(&mut self, writer: &mut W) -> std::io::Result<()> 
    where W: Write,
    {
        if self.header.total_len > DATABUF_SIZE {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, 
                    format!("write_to:invalid packet length({}), exceed {}", self.header.total_len, DATABUF_SIZE)));
        }
        writer.write_all(self.as_bytes())
    }

    pub fn read_from<R: ?Sized>(&mut self, reader: &mut R) -> std::io::Result<()> 
    where R: Read,
    {
        let buf = self.as_bytes_mut();
        let usize_len = std::mem::size_of::<usize>();
        reader.read_exact(&mut buf[..usize_len])?;

        /*
        let bytes:[u8;8] = [buf[0],buf[1],buf[2],buf[3],buf[4],buf[5],buf[6],buf[7]];
        let total_len = usize::from_ne_bytes(bytes);
        */
        /*
        let mut total_len = 0;
        unsafe { std::ptr::copy_nonoverlapping(buf as *const _ as *const usize, &mut total_len as *mut usize, 1); }
        */
        let total_len = unsafe { *(buf as *const _ as *const usize) }; //be careful!

//println!("read_from() total_len = {}", total_len);
        if total_len > DATABUF_SIZE {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, 
                    format!("read_from:invalid packet length({}), exceed {}", total_len, DATABUF_SIZE)));
        }
        reader.read_exact(&mut buf[usize_len..total_len])
    }

    pub fn file_info(&self) -> &mut FileInfo {
        unsafe{
            let obj_raw = &self.data[0] as *const _ as u64;
            let fi = Box::from_raw(obj_raw as *mut FileInfo);
            Box::leak(fi)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe{
            std::slice::from_raw_parts(&self.header as *const _ as *const u8, self.header.total_len)
        }
    }

    pub fn as_bytes_mut(&mut self) -> &mut[u8] {
        unsafe{
            //std::slice::from_raw_parts_mut(&mut self.header as *mut _ as *mut u8, 64*1024)
            std::slice::from_raw_parts_mut(&mut self.header as *mut _ as *mut u8, 64*1024)
        }
    }
}
