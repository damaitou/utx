
use mio::Poll;
use std::io::{Result, Error, ErrorKind};
use std::marker::PhantomData;
use log::{error, trace};

pub trait PollableObject {
    fn register_me (&self, obj_id:usize, poll:&Poll) -> Result<()>;
}

#[derive(Clone)]
struct ObjectBoard<T> {
    board_id: usize,
    objects: Vec<usize>,
    object_pos_seq: u16,
    phantom: PhantomData<T>,
}
impl<T> ObjectBoard<T> {
    fn new(id:usize) -> ObjectBoard<T> {
        ObjectBoard {
            board_id: id,
            objects: vec![0 as usize; 1<<16],
            object_pos_seq: 0,
            phantom: PhantomData,
        }
    }

    pub fn alloc_object_pos(&mut self) -> Option<u16> {
        //todo::what if no object_pos exhausted?
        while self.objects[self.object_pos_seq as usize] != 0 {
            self.object_pos_seq += 1;
        }
        Some(self.object_pos_seq)
    }

    pub fn insert_object(&mut self, obj:T) -> Option<u16> {
        while self.objects[self.object_pos_seq as usize] != 0 {
            self.object_pos_seq += 1;
        }
        let obj_raw = Box::into_raw(Box::new(obj)) as usize;
        self.objects[self.object_pos_seq as usize] = obj_raw;
        trace!("board#{}.insert_object({}) return {}", self.board_id, obj_raw, self.object_pos_seq);
        Some(self.object_pos_seq)
    }

    pub fn place_object(&mut self, obj:T, obj_pos:u16) -> Result<()> {
        match self.objects[obj_pos as usize]  {
            0 => {
                let obj_raw = Box::into_raw(Box::new(obj)) as usize;
                self.objects[obj_pos as usize] = obj_raw;
                Ok(())
            }
            _ => Err(Error::new(ErrorKind::Other, 
                    format!("place_object(),obj_pos={}对应槽位已被占用",obj_pos))),
        }
    }

    pub fn get_object_mut(&self, obj_pos:u16) -> Option<&mut T> {
        match self.objects[obj_pos as usize] {
            0 => None,
            obj_raw => Some(Box::leak(unsafe {Box::from_raw(obj_raw as *mut T)})),
        }
    }

    pub fn get_object_raw(&self, obj_pos:u16) -> Option<usize> {
       // trace!("get_object_raw({}) return {}", obj_pos, self.poll_objects[obj_pos]);
        match self.objects[obj_pos as usize] {
            0 => None,
            obj_raw => Some(obj_raw),
        }
    }

    pub fn remove_object(&mut self, obj_pos:u16) -> bool {
        match self.objects[obj_pos as usize] {
            0 => false,
            obj_raw => {
                trace!("board#{} removing object pos#{}, raw={}", self.board_id, obj_pos, obj_raw);
                drop(unsafe {Box::from_raw(obj_raw as *mut T)}); //important
                self.objects[obj_pos as usize] = 0;
                true
            }
        }
    }
}

pub struct Poller<T:PollableObject> {
    pub poll: Poll, //todo:: make it private
    boards: Vec<ObjectBoard<T>>,
}

impl<T:PollableObject> Poller<T> {
    pub fn new(board_count: usize) -> Poller<T> {
        let mut poller = Poller {
            poll: Poll::new().unwrap(),
            boards: Vec::with_capacity(board_count),
        };
        for i in 0..board_count {
            poller.boards.push(ObjectBoard::new(i));
        }
        poller
    }

    pub fn alloc_object_id(&mut self, board_id:usize) -> Option<usize> {
        match board_id < self.boards.len() {
            true => self.boards[board_id].alloc_object_pos().map(|v|v as usize | board_id<<16),
            false => None,
        }
    }

    pub fn insert_object(&mut self, board_id:usize, obj:T) -> Option<usize> {
        trace!("insert_object(), board_id={}, boards.len()={}", board_id, self.boards.len());
        match board_id < self.boards.len() {
            true => self.boards[board_id].insert_object(obj).map(|v|v as usize | board_id<<16),
            false => None,
        }
    }

    pub fn place_object(&mut self, obj:T, obj_id:usize) -> Result<()> {
        let board_id = obj_id >> 16;
        let obj_pos = (obj_id & ((1<<16)-1)) as u16;
        match board_id < self.boards.len() {
            true => self.boards[board_id].place_object(obj,obj_pos),
            false => Err(Error::new(ErrorKind::Other, format!("place_object(),board_id={} exceed limit",board_id))),
        }
    }

    pub fn get_object_mut(&self, obj_id:usize) -> Option<&mut T> {
        let board_id = obj_id >> 16;
        let obj_pos = (obj_id & ((1<<16)-1)) as u16;
        match board_id < self.boards.len() {
            true => self.boards[board_id].get_object_mut(obj_pos),
            false => None,
        }
    }

    pub fn get_object_raw(&self, obj_id:usize) -> Option<usize> {
        let board_id = obj_id >> 16;
        let obj_pos = (obj_id & ((1<<16)-1)) as u16;
        match board_id < self.boards.len() {
            true => self.boards[board_id].get_object_raw(obj_pos),
            false => None,
        }
    }

    pub fn remove_object(&mut self, obj_id:usize) -> bool {
        let board_id = obj_id >> 16;
        let obj_pos = (obj_id & ((1<<16)-1)) as u16;
        match board_id < self.boards.len() {
            true => self.boards[board_id].remove_object(obj_pos),
            false => false,
        }
    }

    pub fn register_object(&mut self, board_id:usize, obj:T, provided_obj_id: Option<usize>) -> Result<usize> {
        let inserted_obj_id = match provided_obj_id {
            Some(provided_obj_id) =>  {
                self.place_object(obj, provided_obj_id)?;
                provided_obj_id
            }
            None => self.insert_object(board_id, obj)
                        .ok_or(Error::new(ErrorKind::Other, "insert_object() failed"))?,
        };
        let inserted_obj = self.get_object_mut(inserted_obj_id)
            .ok_or(Error::new(ErrorKind::Other, "get_object() failed"))?;

        if let Err(e) = inserted_obj.register_me(inserted_obj_id, &self.poll) {
            error!("poll.register() error:{:?}", e);
            self.remove_object(inserted_obj_id);
            return Err(Error::new(std::io::ErrorKind::Other, 
                    format!("register_object(),注册obj(obj_id={})失败",inserted_obj_id)));
        }
        Ok(inserted_obj_id)
    }
}

