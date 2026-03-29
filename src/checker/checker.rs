
use mylib::config;

fn main() {
    let cfg = match config::TxConfig::new("./tx.json", true, true) {
        Err(e) => {
            println!("error: {}", e);
            for e in e.iter().skip(1) {
                println!("caused by: {}", e);
            }
            ::std::process::exit(1);
        } 
        Ok(cfg) => cfg,
    };

    for fcc in &cfg.fccs {
        println!("{:?}", fcc);
    }

    //println!("{:?}",cfg);
}
