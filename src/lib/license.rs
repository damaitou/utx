
use std::os::raw::c_int;
use block_cipher_trait::BlockCipher;
use generic_array::{GenericArray};
use generic_array::typenum::{U8};
use serde::{Serialize, Deserialize};
use std::io::{Result, Error, ErrorKind};

#[link(name = "utx", kind = "static")]
extern "C" {
    fn list_if_macs(
        buf: *const u8, 
        buf_len: c_int,
    ) -> c_int;
}

const CHARS: [u8;64] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Serialize, Deserialize)]
pub struct License {
    pub license_id: String,
    pub product: String,
    pub customer: String,
    pub issue_date: String,
    pub expire_date: String,
}
impl License {
    fn get_hardware_uid() -> Result<String> {
        let mac_bytes = [0 as u8; 65];
        match unsafe { list_if_macs(mac_bytes.as_ptr(), mac_bytes.len() as c_int) } {
            -1 => Err(Error::new(ErrorKind::Other, "query hardware information failed")),
            n => Ok(String::from_utf8_lossy(&mac_bytes[..n as usize]).to_string()),
        }
    }

    fn char_to_hex(b: u8) -> Result<u8> {
        match b  as char {
            'A'..='Z' => Ok(b - 'A' as u8),
            'a'..='z' => Ok(b - 'a' as u8 + 26),
            '0'..='9' => Ok(b - '0' as u8 + 52),
            '+' => Ok(62),
            '/' => Ok(63),
            '=' => Ok(0),
            _ => Err(Error::new(ErrorKind::Other, "invalid base64 string")),
        }
    }

    fn base64_encode(buffer:&[u8]) -> String {
        let count = buffer.len()/3;
        let remain = buffer.len()%3;
        let mut result = vec![0 as u8; 4*(count + match remain {0=>0, _=>1})];

        for i in 0..count {
            let b0 = buffer[i*3];
            let b1 = buffer[i*3+1];
            let b2 = buffer[i*3+2];
            let c0 = b0 >> 2;
            let c1 = ((b0 << 4) & 0x30) | (b1 >> 4);
            let c2 = ((b1 << 2) & 0x3c) | (b2 >> 6);
            let c3 = b2 & 0x3f;
            result[i*4] = CHARS[c0 as usize];
            result[i*4+1] = CHARS[c1 as usize];
            result[i*4+2] = CHARS[c2 as usize];
            result[i*4+3] = CHARS[c3 as usize];
        }

        match remain {
            0 => {},
            1 => {
                let b0 = buffer[count*3];
                let c0 = b0 >> 2;
                let c1 = (b0 << 4) & 0x30;
                result[count*4] = CHARS[c0 as usize];
                result[count*4+1] = CHARS[c1 as usize];
                result[count*4+2] = '=' as u8;
                result[count*4+3] = '=' as u8;
            }
            2|_ => {
                let b0 = buffer[count*3];
                let b1 = buffer[count*3+1];
                let c0 = b0 >> 2;
                let c1 = ((b0 << 4) & 0x30) | (b1 >> 4);
                let c2 = (b1 << 2) & 0x3c;
                result[count*4] = CHARS[c0 as usize];
                result[count*4+1] = CHARS[c1 as usize];
                result[count*4+2] = CHARS[c2 as usize];
                result[count*4+3] = '=' as u8;
            }
        }
        String::from_utf8_lossy(&result).to_string()
    }

    fn base64_decode(input:&str, output:&mut [u8]) -> Result<usize> {
        if input.len()%4 != 0 {
            return Err(Error::new(ErrorKind::Other, "invalid length of base64 string"));
        }
        if output.len() != input.len()*3/4 {
            return Err(Error::new(ErrorKind::Other, "input/output length not matched"));
        }

        let count = input.len()/4;
        let input_bytes: &[u8] = input.as_bytes();
        for i in 0..count {
            let c0 = License::char_to_hex(input_bytes[i*4]).unwrap();
            let c1 = License::char_to_hex(input_bytes[i*4+1]).unwrap();
            let c2 = License::char_to_hex(input_bytes[i*4+2]).unwrap();
            let c3 = License::char_to_hex(input_bytes[i*4+3]).unwrap();

            let b0 = (c0 << 2) | (c1 >> 4); 
            let b1 = (c1 << 4) | (c2 >> 2); 
            let b2 = (c2 << 6) | c3;
            output[i*3] = b0;
            output[i*3+1] = b1;
            output[i*3+2] = b2;
        }

        Ok(
            match input_bytes[input.len()-1] as char {
                '=' => 
                    match input_bytes[input.len()-2] as char {
                        '=' => output.len()-2,
                        _ => output.len()-1,
                    }
                _ => output.len(),
            }
        )
    }

    pub fn encode_string(src: &str) -> Result<String> {
        let key = License::get_hardware_uid()?;
        let dgst = md5::compute(key.as_bytes());
        let mut inner_key = GenericArray::<u8,U8>::default();
        //XOR the first 8 bytes and the last 8 bytes to construct a key
        for (i, &b) in dgst.0.iter().enumerate() {
            inner_key[i%8] = inner_key[i%8] ^ b;
        }

        //println!("inner_key.len()={}", inner_key.len());
        let len = 8*(1+(src.len()-1)/8);
        let mut buffer = vec![0; len];
        buffer[0..src.len()].copy_from_slice(src.as_bytes());
        //println!("before encrypt:{:x?}",buffer);

        let cipher = des::Des::new(&inner_key);
        for i in 0..len/8 {
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut buffer[i*8..i*8+8]));
        }
        //println!("after encrypt:{:x?}",buffer);
        Ok(License::base64_encode(&buffer))
    }

    pub fn decode_string(src: &str) -> Result<String> {
        let mut buffer = vec![0 as u8; src.len()*3/4];
        let len = License::base64_decode(src, &mut buffer)?;

        let key = License::get_hardware_uid()?;
        let dgst = md5::compute(key.as_bytes());
        let mut inner_key = GenericArray::<u8,U8>::default();
        for (i, &b) in dgst.0.iter().enumerate() {
            inner_key[i%8] = inner_key[i%8] ^ b;
        }

        //println!("inner_key.len()={}", inner_key.len());
        let cipher = des::Des::new(&inner_key);
        for i in 0..len/8 {
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut buffer[i*8..i*8+8]));
        }
        //println!("after decrypt:{:x?}",buffer);
        Ok(String::from_utf8_lossy(&buffer[..len]).to_string())
    }

    pub fn encode_license(lic: &License) -> Result<String> {
        match serde_json::to_string(lic) {
            Ok(line) => License::encode_string(&line),
            Err(e) => Err(Error::new(ErrorKind::Other, format!("serde_json::to_string() failed:{:?}",e))),
        }
    }

    pub fn decode_license(lic_string: &str) -> Result<License> {
        match License::decode_string(lic_string) {
            Ok(line) => {
                println!("license_json={}", line);
                let line = line.trim_end_matches('\0');
                match serde_json::from_str(line) {
                    Ok(lic) => Ok(lic),
                    Err(e) =>  Err(Error::new(ErrorKind::Other, format!("serde_json::from_str() failed:{:?}",e))),
                }
            },
            Err(e) => Err(e),
        }
    }
}

