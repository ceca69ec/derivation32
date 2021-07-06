// derivation32/src/main.rs
// 20210706
// ceca69ec8e1bcad6c6d79e1dcf7214ff67766580a62b7d19a6fb094c97b4f2dc

//! Receives address, hex entropy, wif secret or extended key and show
//! information and/or derivation about it. Secret keys can be encrypted.

use derivation32::{handle_arguments, init_clap};

/// Whirlpool of the project.
fn main() {
    handle_arguments(init_clap().get_matches()).unwrap_or_else(|err| {
        clap::Error::with_description(
            &err.message(),
            clap::ErrorKind::InvalidValue
        ).exit();
    });
}
