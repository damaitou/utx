pub mod audit;
pub mod config;
pub mod license;
pub mod context;
pub mod ftp;
pub mod sftp;
pub mod utx;
pub mod virus;
pub mod util;
pub mod word_checker;
pub mod version;
pub mod file_list_history;

#[macro_use]
extern crate mysql;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;

pub mod errors;
pub mod def;

/*
pub mod errors {
    error_chain!{
        foreign_links {
            Fmt(::std::fmt::Error);
            Io(::std::io::Error) #[cfg(unix)];
        }

        errors {
            RecoverableError(code:u32, msg:String) {
                description("Error")
                display("Error:{},Message:{}", code, msg)
            }

            UnrecoverableError(code:u32, msg:String) {
                description("Unrecoverable Error")
                display("Unrecoverable Error:{},Message:{}", code, msg)
            }
        }
    }
}
*/

