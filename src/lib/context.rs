extern crate serde;
extern crate bincode;
use serde::{Serialize, Deserialize};

pub const KIND_LISTER: usize = 0;
pub const KIND_PULLER: usize = 1;
pub const KIND_PUSHER: usize = 2;
pub const KIND_UTX: usize = 3;
pub const KIND_AGENT: usize = 4;
pub const KIND_UDP: usize = 5;
pub const KIND_WATCHER: usize = 6;
pub const KIND_CONTROL: usize = 7;
pub const KIND_TIMER: usize = 8;
pub const KIND_NAMES: [&str; 9] = [
    "lister", 
    "puller", 
    "pusher", 
    "utx", 
    "agent",
    "udp",
    "watcher",
    "control",
    "timer",
];

pub fn calc_thread_id(channel: usize, kind: usize, index: usize) -> usize {
    channel*1000 + kind*100 + index
}

pub fn from_thread_id(id: usize) -> (usize, usize, usize) {
    let channel = id / 1000;
    let kind = (id % 1000) / 100;
    let index = id % 100;
    (channel, kind, index)
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ThreadAction {
    //status report from working thread
    ThreadInitOk = 1,
    ThreadInitFail,
    ThreadReady,
    ThreadErrorAndExit,

    //command to working thread
    CmdQuit,
    CmdListerRun,
    CmdPullerRun,
    CmdPullerPatrol,
    CmdPusherRun,
    CmdPusherPatrol,
    CmdUtxRun,

    //response from working thread
    RspListerFile,
    RspListerBloc,
    RspPullerFile,
    RspPullerBloc,

    //ctrl actions
    CtrlInit,
    CtrlReload,
    CtrlListFileChannel,
    CtrlStartFileChannel,
    CtrlStopFileChannel,
    CtrlListDatagramChannel,
    CtrlStartDatagramChannel,
    CtrlStopDatagramChannel,
    CtrlOk,
    CtrlFail,

    //timer
    TimerInit,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ThreadMsg {
    pub channel: usize,
    pub kind: usize,
    pub id: usize,
    //pub action: String,
    pub action: ThreadAction,
    pub object: String,
}

pub const BOOTING:usize = 0;
pub const RUNNING:usize = 1;
pub const STOPPED:usize = 2;
pub const DEFUNC:usize = 3;
pub const NO_CONFIG:usize = 4;
pub const STATUS_NAMES: [&str;5] = ["booting", "running", "stopped", "defunc", "no_config"];

