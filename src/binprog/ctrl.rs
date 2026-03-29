
use std::os::unix::net::{UnixStream};
use std::env;
use mylib::util;
use mylib::context::{self, ThreadAction, ThreadMsg, KIND_CONTROL};
use mylib::errors::*;

struct Controller {
    stream: UnixStream,
}

impl Controller {
    //fn new(prog_name: &str, pp: &util::ProgParam) -> Result<(Controller)> {
    fn new(prog_name: &str, utx_root: &str) -> Result<Controller> {
        let ctrl = Controller {
            stream: util::unix_connect(&utx_root, prog_name)?,
        };
        ctrl.send(ThreadAction::CtrlInit, "")?;
        Ok(ctrl)
    }

    fn send(&self, action: ThreadAction, object: &str) -> Result<()> {
        let msg = ThreadMsg {
            channel: 0,
            kind: KIND_CONTROL,
            id: context::calc_thread_id(0, KIND_CONTROL, 0),
            action: action,
            object: object.to_string(),
        };
        bincode::serialize_into(&self.stream, &msg).chain_err(||"发送序列化对象失败")?;
        Ok(())
    }

    fn recv(&self) -> Result<ThreadMsg> {
        let resp:ThreadMsg = bincode::deserialize_from(&self.stream).chain_err(||"接收序列化对象失败")?;
        Ok(resp)
    }
}

//fn run(prog_name: &str, pp: &util::ProgParam) -> Result<()> {
fn run(prog_name: &str, utx_root: &str) -> Result<()> {

    let ctrl = Controller::new(prog_name, utx_root).chain_err(||"创建Controller失败")?;
    loop {
        let mut input = String::new();
        println!("input>");
        std::io::stdin().read_line(&mut input).expect("Failed to read line");

        let input = input.trim_end_matches(|c|c=='\r'||c=='\n');
        let args:Vec<&str> = input.split(' ').collect();
        let cmd = args[0].to_uppercase();
        let action = match cmd.as_str() {
            "EXIT"|"QUIT" => break,
            "RELOAD" => ThreadAction::CtrlReload,
            "LIST_FILE_CHANNEL" => ThreadAction::CtrlListFileChannel,
            "LIST_DATAGRAM_CHANNEL" => ThreadAction::CtrlListDatagramChannel,
            "START_FILE_CHANNEL" => ThreadAction::CtrlStartFileChannel,
            "STOP_FILE_CHANNEL" => ThreadAction::CtrlStopFileChannel,
            "START_DATAGRAM_CHANNEL" => ThreadAction::CtrlStartDatagramChannel,
            "STOP_DATAGRAM_CHANNEL" => ThreadAction::CtrlStopDatagramChannel,
            _ => {
                eprintln!("invalid command, please try again. exit/quit to exit");
                continue;
            }
        };

        match action {
            ThreadAction::CtrlStartFileChannel|
            ThreadAction::CtrlStopFileChannel|
            ThreadAction::CtrlStartDatagramChannel|
            ThreadAction::CtrlStopDatagramChannel => 
            {
                if args.len() < 2 {
                    eprintln!("invalid command, please specified a channel number");
                    continue;
                } else {
                    let channel:i32 = args[1].parse().unwrap_or(-1);
                    if channel < 0 || channel > 255 {
                        eprintln!("invalid channel number, should between[0-255]");
                        continue;
                    } else {
                        ctrl.send(action, args[1])?; 
                    }
                }
            }
            _ => ctrl.send(action, "")?
        }
        /*
        match cmd.as_str() {
            "EXIT"|"QUIT" => break,
            "LIST_FILE_CHANNEL" | "LIST_DATAGRAM_CHANNEL" | "RELOAD" => ctrl.send(cmd.as_str(), "")?,
            "START_FILE_CHANNEL" | "STOP_FILE_CHANNEL" | 
            "START_DATAGRAM_CHANNEL" | "STOP_DATAGRAM_CHANNEL" => {
                if args.len() < 2 {
                    eprintln!("invalid command, please specified a channel number");
                    continue;
                } else {
                    let channel:i32 = args[1].parse().unwrap_or(-1);
                    if channel < 0 || channel > 255 {
                        eprintln!("invalid channel number, should between[0-255]");
                        continue;
                    } else {
                        ctrl.send(cmd.as_str(), args[1])?; 
                    }
                }
            }
            _ => {
                eprintln!("invalid command, please try again. exit/quit to exit");
                continue;
            }
        }
        */

        let resp = ctrl.recv()?;
        eprintln!("{:?} {}", resp.action, resp.object);
    }

    Ok(())
}

fn main() {
    let mut args = env::args();
    args.next();
    let target_name = match args.next() {
        None => "fpull".to_string(),
        Some(arg) => arg,
    };

    //let pp = util::parse_args();
    let utx_root = util::env_utx_root().unwrap(); //todo

    //if let Err(e) = run(&target_name, &pp) {
    if let Err(e) = run(&target_name, &utx_root) {
        util::log_error(&e);
        std::process::exit(-1);
    }
}

