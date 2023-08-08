use rand::{distributions::Alphanumeric, Rng};

pub fn generate_random_state() -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(42)
        .map(char::from)
        .collect()
}
