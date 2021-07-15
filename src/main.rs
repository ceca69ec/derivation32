//! Receives address, hex entropy, wif secret or extended key and show
//! information and/or derivation about it. Secret keys can be encrypted.

use derivation32::{handle_arguments, init_clap};

/// Whirlpool of the project.
fn main() {
    handle_arguments(init_clap().get_matches()).unwrap_or_else(|err| {
        eprintln!("\x1b[31m\x1b[1merror\x1b[m: {}", err);
        std::process::exit(96);
    });
}
