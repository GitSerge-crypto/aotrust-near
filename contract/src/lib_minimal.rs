use near_sdk::{near, store::LookupMap};

#[near(contract_state)]
pub struct MerkleAnchor {
    roots: LookupMap<u64, String>,
    sequence: u64,
}

impl Default for MerkleAnchor {
    fn default() -> Self {
        Self {
            roots: LookupMap::new(b"r"),
            sequence: 0,
        }
    }
}

#[near]
impl MerkleAnchor {
    #[init]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn anchor(&mut self, root: String) -> u64 {
        assert_eq!(
            near_sdk::env::predecessor_account_id(),
            near_sdk::env::current_account_id(),
            "Only contract account may anchor roots"
        );
        let seq = self.sequence;
        self.roots.insert(seq, root);
        self.sequence += 1;
        seq
    }

    pub fn get_root(&self, seq: u64) -> Option<&String> {
        self.roots.get(&seq)
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}