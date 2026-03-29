
use std::env;
//use std::{thread, time};

mod watch;
use crate::watch::{FileChannelWatcher};
use mylib::util;
use std::io::Write;

fn main()
{
    let local_root_path = "/home/damaitou/xx";

    let mut args = env::args();
    args.next().unwrap();
    match args.next() {
        Some(arg) => {
            let abs_file = format!("{}/{}", local_root_path, &arg);
            let mut f = util::ensure_file(&abs_file).expect("ensure_file failed");
            let _ = f.write(b"some testing data\n");
            drop(f);
            //thread::sleep(time::Duration::from_secs(1));
        },
        None => watch_dirs(local_root_path),
    }
}

fn watch_dirs(local_root_path: &str) 
{
    let mut watcher = FileChannelWatcher::new(0, &local_root_path, 1).expect("create FileChannelWatcher failed.");
    watcher.dump();

    println!("----------------");
    watcher.add_sub_dirs_to_watch("", 10-1); //to test conflict situation
    watcher.dump();

    let mut buffer = [0u8; 4096];
    loop {
        let events = watcher.notify.read_events_blocking(&mut buffer).expect("failed to read inotify events");
        for event in events {
            if event.name.is_none() {
                continue;
            }
            println!("channel {} file {:?} detected", watcher.channel, event);

            let file = match event.name.unwrap().to_str() {
                Some(name) => name.to_string(),
                None => {
                    eprintln!("'{:?}' is not a valid unicode file name, skipped", event.name.unwrap());
                    continue;
                }
            };

            let _ = watcher.is_file_detected(event.wd, &event.mask, &file);
            println!("----------------");
            watcher.dump();
        }
    }
}

