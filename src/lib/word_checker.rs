
#[link(name = "trie", kind = "static")]
extern "C" {
    fn trie_new() -> u64;
    fn trie_insert(handle: u64, word: *const u8);
    fn trie_match(handle: u64, buf: *const u8, len: i32) -> i32;
    fn trie_clone(handle: u64);
    fn trie_drop(handle: u64);
    fn trie_stats();
}

const PERMISSION_DENY: u32 = 0;
const PERMISSION_ALLOW: u32 = 1;

#[derive(Debug)]
pub struct WordChecker {
    handle: u64,
    permission: u32,
}

impl Clone for WordChecker {
    fn clone(&self) -> Self {
        unsafe {
            trie_clone(self.handle);
        };
        WordChecker {
            handle: self.handle,
            permission: self.permission,
        }
    }
}

impl Drop for WordChecker {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                trie_drop(self.handle);
                self.handle = 0;
            }
        }
    }
}

impl WordChecker {
    pub fn new() -> Option<WordChecker> {
        unsafe {
            let handle = trie_new();
            match handle {
                0 => {
                    return None;
                }
                h => {
                    let wc = WordChecker {
                        handle: h,
                        permission: PERMISSION_DENY,
                    };
                    return Some(wc);
                }
            }
        }
    }

    pub fn insert(&self, word: &str) {
        let mut w = word.to_string();
        w.push('\0');
        unsafe {
            trie_insert(self.handle, w.as_ptr());
        }
    }

    fn exist(&self, buf: &[u8]) -> bool {
        unsafe {
            return match trie_match(self.handle, buf.as_ptr(), buf.len() as i32) {
                1 => true,
                _ => false,
            };
        }
    }

    pub fn allow(&self, buf: &[u8]) -> bool {
        let exists = self.exist(buf);
        return exists && (self.permission == PERMISSION_ALLOW)
            || !exists && (self.permission == PERMISSION_DENY);
    }

    pub fn stats(&self) {
        unsafe { 
            trie_stats();
        }
    }
}

