
extern crate cc;
extern crate chrono;
//use std::{ env, error::Error, fs::File, io::{BufWriter, Write}, path::Path,};
use chrono::{Local, DateTime};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    cc::Build::new()
        .file("src/c/cutx.c")
        .file("src/c/sutx.c")
        .include("src/c")
        .compile("libutx.a");

    cc::Build::new()
        .file("src/c/radix_trie.c")
        .include("src/c")
        .compile("libtrie.a");

    cc::Build::new()
        .file("src/c/file_magic.c")
        .compile("libfilemagic.a");

    /*
    cc::Config::new()
        .file("src/c/scan_virus.c")
        .include("src/c")
        .compile("libvirus.a");
    */

    let now: DateTime<Local> = Local::now();
    let now_str = now.format("%Y/%m/%d-%H:%M:%S");
    println!("cargo:rustc-env=BUILD_TIME={}", now_str);

    /*
    let out_dir = env::var("OUT_DIR")?;
    let dest_path = Path::new(&out_dir).join("build_time.txt");
    let mut f = BufWriter::new(File::create(&dest_path)?);
    write!(f, "{}", now_str)?;
    */

    /*
    for (key, value) in env::vars() {
        write!(f, "{}: {}\n", key, value)?;
    }
    */

    //println!(r"cargo:rustc-link-lib=clamav");
    println!(r"cargo:rustc-link-search=/usr/local/lib");
    println!(r"cargo:rustc-link-lib=magic");

    Ok(())
}

