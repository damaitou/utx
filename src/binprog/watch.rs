extern crate inotify;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use log::{debug, error, info, warn};
use mylib::errors::*;
use std::collections::HashMap;

const MAX_SUBDIR_DEPTH: usize = 10;

pub struct FileChannelWatcher {
    pub id: usize,
    pub channel: usize,
    pub local_root_path: String,
    pub notify: Inotify,
    pub root_wd: WatchDescriptor,
    wds: HashMap<WatchDescriptor, (String, usize)>,
    wds_index: HashMap<String, WatchDescriptor>,
}

impl FileChannelWatcher {
    #[allow(dead_code)]
    pub fn dump(&self) {
        for wd in &self.wds {
            println!("{:?}", wd);
        }
    }

    pub fn is_file_detected(
        &mut self,
        wd: WatchDescriptor,
        mask: &EventMask,
        name: &str,
    ) -> Option<String> {
        let (rel_name, depth) = match self.root_wd == wd {
            true => (name.to_string(), MAX_SUBDIR_DEPTH),
            false => match self.wds.get(&wd) {
                Some((sub_dir, depth)) => (format!("{}/{}", sub_dir, name), depth.clone()),
                None => {
                    warn!(
                        "OOPS! WatchDescriptor {:?} detected but not found in the watch list",
                        wd
                    );
                    return None;
                }
            },
        };

        let is_dir = mask.contains(EventMask::ISDIR);
        match is_dir {
            false => {
                if mask.contains(EventMask::CLOSE_WRITE) || mask.contains(EventMask::MOVED_TO) {
                    return Some(rel_name);
                }
            }
            true => {
                if mask.contains(EventMask::CREATE) && !name.starts_with("/") {
                    //当根目录下创建子目录时,加入到watch清单
                    self.add_a_sub_dir(&rel_name, depth - 1);
                } else if mask.contains(EventMask::DELETE) {
                    //当根目录下删除子目录时,从watch清单删除
                    self.remove_a_sub_dir(wd, &rel_name);
                }
            }
        }
        None
    }

    pub fn remove_a_sub_dir(&mut self, _wd: WatchDescriptor, sub_dir: &str) {
        match self.wds_index.remove(sub_dir) {
            Some(wd_to_remove) => {
                self.wds.remove(&wd_to_remove);
                let _ = self.notify.rm_watch(wd_to_remove);
                info!("removed '{}/{}' from watch", self.local_root_path, sub_dir);
            }
            None => warn!("'{}' not exists, cannot be removed", sub_dir),
        }
    }

    pub fn add_a_sub_dir(&mut self, sub_dir: &str, depth: usize) {
        if depth == 0 {
            return;
        }

        let abs_path = format!("{}/{}", self.local_root_path, sub_dir);
        /*
        match std::fs::metadata(&abs_path) {
            Ok(meta) => {
                if !meta.is_dir() { return; }
            }
            Err(e) => {
                error!("get metadata of '{}' error:{:?}", &abs_path, e);
                return;
            }
        }
        */

        match self.notify.add_watch(
            &abs_path,
            WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::CREATE | WatchMask::DELETE,
        ) {
            Ok(wd) => {
                let wd2 = wd.clone();
                self.wds.insert(wd, (sub_dir.to_string(), depth));
                self.wds_index.insert(sub_dir.to_string(), wd2);
                info!("add_to_watch: channel={}, dir={}", self.channel, abs_path);

                //in case of creating dir1/dir2/dir3/... simultaneously,
                //dir2 and dir3 and other subdirecotries are created before dir1 being added to watch
                self.add_sub_dirs_to_watch(&sub_dir, depth - 1);
            }
            Err(e) => {
                error!("add '{}' to watch failed:{:?}", abs_path, e);
            }
        }
    }

    pub fn add_sub_dirs_to_watch(&mut self, parent_sub_dir: &str, depth: usize) {
        if depth == 0 {
            return;
        }

        let parent_path = match parent_sub_dir.len() {
            0 => self.local_root_path.clone(),
            _ => format!("{}/{}", self.local_root_path, parent_sub_dir),
        };
        debug!(
            "add_sub_dirs_to_watch, parent_path='{}', depth={}",
            parent_path, depth
        );

        let entries = match std::fs::read_dir(&parent_path) {
            Ok(val) => val,
            Err(e) => {
                error!(
                    "channel {} add_sub_dirs_to_watch() read_dir failed:{:?}",
                    self.channel, e
                );
                return;
            }
        };

        for entry in entries {
            if let Ok(entry) = entry {
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        if let Some(file_name) = entry.file_name().to_str() {
                            //子目录不能以'.'开头
                            if file_name.starts_with(".") {
                                info!("'{}' starts_with '.', cannot be added to watch", file_name);
                                continue;
                            }

                            let sub_dir = match parent_sub_dir.len() {
                                0 => file_name.to_string(),
                                _ => format!("{}/{}", parent_sub_dir, file_name),
                            };
                            debug!("sub_dir='{}'", sub_dir);

                            //加入到inotify监控
                            let abs_path = format!("{}/{}", self.local_root_path, sub_dir);
                            match self.notify.add_watch(
                                &abs_path,
                                WatchMask::CLOSE_WRITE
                                    | WatchMask::MOVED_TO
                                    | WatchMask::CREATE
                                    | WatchMask::DELETE,
                            ) {
                                Ok(wd) => {
                                    let wd2 = wd.clone();
                                    self.wds.insert(wd, (sub_dir.to_string(), depth));
                                    self.wds_index.insert(sub_dir.to_string(), wd2);
                                    info!(
                                        "add_to_watch: channel={}, dir={}",
                                        self.channel, abs_path
                                    );
                                }
                                Err(e) => {
                                    error!("add '{}' to watch failed:{:?}", abs_path, e);
                                }
                            }

                            //处理下一层子目录
                            self.add_sub_dirs_to_watch(&sub_dir, depth - 1);
                        }
                    }
                }
            }
        }
    }

    pub fn new(channel: usize, local_root_path: &str, id: usize) -> Result<FileChannelWatcher> {
        let mut notify = Inotify::init().chain_err(|| "Failed to initialize inotify")?;

        std::fs::create_dir_all(local_root_path)
            .chain_err(|| format!("ensure_path()创建目录{}失败", local_root_path))?;

        let wd = notify
            .add_watch(
                local_root_path,
                WatchMask::CLOSE_WRITE
                    | WatchMask::MOVED_TO
                    | WatchMask::CREATE
                    | WatchMask::DELETE,
            )
            .chain_err(|| "Failed to add inotify watch")?;
        info!("add_to_watch: channel={}, dir={}", channel, local_root_path);

        let mut fcw = FileChannelWatcher {
            id: id,
            channel: channel,
            local_root_path: local_root_path.to_string(),
            notify: notify,
            root_wd: wd,
            wds: HashMap::new(),
            wds_index: HashMap::new(),
        };
        fcw.add_sub_dirs_to_watch("", MAX_SUBDIR_DEPTH - 1);

        Ok(fcw)
    }
}
