#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemporalPolicy {
    Historical(u64),
    Current,
    Window { start: u64, end: u64 },
    ResealRequired { after: u64 },
}

impl TemporalPolicy {
    pub fn accepts(&self, e_open: u64, e_seal: u64) -> bool {
        match self {
            TemporalPolicy::Historical(e_hist) => *e_hist == e_seal,
            TemporalPolicy::Current => e_open >= e_seal,
            TemporalPolicy::Window { start, end } => e_open >= *start && e_open <= *end,
            TemporalPolicy::ResealRequired { .. } => e_open >= e_seal,
        }
    }

    pub fn required_wrapper_epoch(&self, e_open: u64, e_seal: u64) -> u64 {
        match self {
            TemporalPolicy::Historical(_) => e_seal,
            TemporalPolicy::Current => e_open,
            TemporalPolicy::Window { .. } => e_open,
            TemporalPolicy::ResealRequired { after } => {
                if e_open <= *after {
                    e_seal
                } else {
                    e_open
                }
            }
        }
    }
}
