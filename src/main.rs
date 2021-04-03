#![warn(clippy::all)]

use clap::Clap;
use sequoia_openpgp::packet::UserID;

mod generate;
mod output;

fn get_userid() -> UserID {
    let opts: Opts = Opts::parse();
    UserID::from_address(
        opts.username.clone().into(),
        opts.comment.clone(),
        opts.email,
    )
    .unwrap()
}

fn get_secret_phrase() -> String {
    let opts: Opts = Opts::parse();
    opts.secret
}

fn main() {
    let (cert, revocation) = generate::cert_and_revoc();
    output::print_cert(&cert);
    output::print_revocation(&revocation);
    output::print_keys(&cert);
}

/// `cfs_openpgp` generates a valid `OpenPGP` certificate based on the username, email, and secret
/// you provide. Though the ASCII-armored representation of the cert will differ, the same input
/// should always produce the same keys. Obviously, this is highly insecure and should never be used
/// or unicorns and kittens will cry.
#[derive(Clap)]
#[clap(version = "0.1.0", author = "Mo Ismailzai <mo@ismailzai.com>")]
struct Opts {
    #[clap(short, long)]
    comment: Option<String>,
    #[clap(short, long, default_value = "alice@example.com")]
    email: String,
    #[clap(short, long)]
    secret: String,
    #[clap(short, long, default_value = "Alice")]
    username: String,
}
