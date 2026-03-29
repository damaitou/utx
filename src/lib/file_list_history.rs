
extern crate serde;
extern crate bincode;
use serde::{Serialize, Deserialize};
use std::path::Path;
use std::collections::HashMap;
use std::fs::File;
use log::{error, warn, /*info,*/ debug};
use crate::errors::*;

#[derive(Serialize, Deserialize)]
pub struct FileListHistory {
    path: String,
    //file fetched history: file_marker -> (counter when file added to history, counter when file lastly hit)
    map: HashMap<String, (usize, usize)>,
    pub fetch_counter: usize,
    pub this_fetch_add: u32,  //how many files added into map during this_fetch
    pub this_fetch_hit: u32,  //how many files in map hit during this_fetch
}

impl FileListHistory {
    pub fn new(path: &str) -> FileListHistory {
        match FileListHistory::deserialize_from(path) {
            Some(history) => history,
            None => {
                FileListHistory {
                    path: path.to_string(),
                    map: HashMap::new(),
                    fetch_counter: 0,
                    this_fetch_add: 0,
                    this_fetch_hit: 0,
                }
            }
        }
    }

    pub fn start_a_fetch(&mut self) {
        self.fetch_counter += 1;
        self.this_fetch_add = 0;
        self.this_fetch_hit = 0;
    }

    /* if file_marker in map return true, else return false
     */
    pub fn hit_a_file(&mut self, file_marker: String) -> bool {
        debug!("file_marker={}", file_marker);
        match self.map.get_mut(&file_marker) {
            None => { 
                debug!("file_marker '{}' added to cache_files", file_marker);
                self.map.insert(file_marker, (self.fetch_counter, self.fetch_counter)); 
                self.this_fetch_add += 1;
                false
            },
            Some(v) => {
                v.1 = self.fetch_counter;
                self.this_fetch_hit += 1;
                //debug!("file '{}' has been fetched, listed {} times", name, (v.1 as i64 - v.0 as i64)+1);
                true
            }
        }
    }

    pub fn invalidate(&mut self) -> Result<()> {
        if self.map.len() > (self.this_fetch_add + self.this_fetch_hit) as usize /*&& map.len() > 1000*/ { 
            debug!("map.len({}) > (add={} + hit={}), cleanup start...", self.map.len(), self.this_fetch_add, self.this_fetch_hit);
            let counter = self.fetch_counter;
            self.map.retain(|_k,v|counter <= v.1 + 10); //todo
            debug!("cleanup done, map.len={}", self.map.len());
            self.serialize_to(&self.path).map_err(|e| format!("serialize failed:{}",e))?;
        } else if self.this_fetch_add > 0 {
            self.serialize_to(&self.path).map_err(|e| format!("serialize failed:{}",e))?;
        }
        Ok(())
    }

    fn serialize_to(&self, path:&str) ->Result<()> {
        let dir = Path::new(path).parent().ok_or(format!("invalid path:{:?}", path))?;
        if let Ok(_) = std::fs::create_dir_all(dir) {
            let f = File::create(path).chain_err(||"create serialize file error")?;
            bincode::serialize_into(&f, self).chain_err(||"serialize cache_files error")?;
        }
        Ok(())
    }

    fn deserialize_from(path: &str) ->Option<FileListHistory> {
        if let Ok(f) = File::open(path) {
            match bincode::deserialize_from(&f) {
                Ok(history) => Some(history),
                Err(e) => { error!("deserialize cache_files failed:{:?}", e); None }
            }
        } else {
            warn!("open '{}' failed.", path);
            None
        }
    }

    #[allow(dead_code)]
    fn dump(&self) {
        for (k,v) in &self.map {
            println!("{}->({},{})", k, v.0, v.1);
        }
    }
}

