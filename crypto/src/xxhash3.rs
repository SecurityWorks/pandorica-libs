use xxhash_rust::xxh3::xxh3_64;

pub struct XxHash3;

impl XxHash3 {
    pub fn generate_hash(data: &[u8]) -> u64 {
        xxh3_64(data)
    }

    pub fn verify_hash(data: &[u8], hash: u64) -> bool {
        xxh3_64(data) == hash
    }
}
