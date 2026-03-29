
use error_chain::*;

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

