#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rights(pub u16);

impl Rights {
    pub const READ: Rights = Rights(1 << 0);
    pub const WRITE: Rights = Rights(1 << 1);
    pub const APPEND: Rights = Rights(1 << 2);
    pub const DELETE: Rights = Rights(1 << 3);
    pub const DECRYPT: Rights = Rights(1 << 4);
    pub const DELEGATE: Rights = Rights(1 << 5);
    pub const EXPORT: Rights = Rights(1 << 6);
    pub const EXECUTE: Rights = Rights(1 << 7);
    pub const ROTATE: Rights = Rights(1 << 8);
    pub const SEAL: Rights = Rights(1 << 9);
    pub const UNSEAL: Rights = Rights(1 << 10);

    pub const fn empty() -> Rights {
        Rights(0)
    }

    pub const fn union(self, other: Rights) -> Rights {
        Rights(self.0 | other.0)
    }

    pub const fn contains_all(self, required: Rights) -> bool {
        (self.0 & required.0) == required.0
    }

    pub const fn bits(self) -> u16 {
        self.0
    }
}
