#![allow(dead_code)]

pub struct ChannelSlot<T> {
    _channel: u8,
    pub obj: Option<T>,
}

/*
impl<T> ChannelSlot<T> {
    fn get_obj_mut(&mut self) -> &mut T {
        self.obj.as_mut().unwrap()
    }

    fn get_obj(&self) ->  &T {
        self.obj.as_ref().unwrap()
    }
}
*/

#[allow(dead_code)]
pub struct ChannelContainer<T> {
    slots: Vec<ChannelSlot<T>>,
}

impl<T> ChannelContainer<T> {
    pub fn new() -> ChannelContainer<T> {
        let mut rt = ChannelContainer { slots: Vec::new() };

        for i in 0..256 {
            let slot = ChannelSlot {
                _channel: i as u8,
                obj: None,
            };
            rt.slots.push(slot);
        }

        rt
    }

    pub fn get_slot(&self, channel: u8) -> &ChannelSlot<T> {
        &self.slots[channel as usize]
    }

    pub fn get_slot_mut(&mut self, channel: u8) -> &mut ChannelSlot<T> {
        &mut self.slots[channel as usize]
    }

    pub fn place(&mut self, channel: u8, obj: T) {
        let slot = self.get_slot_mut(channel);
        slot.obj = Some(obj);
    }
}
