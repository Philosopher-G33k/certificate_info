pub mod config {
    use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Config {
    /// Name of the person to greet
    #[arg(short, long)]
    pub domain: String,

    // Number of times to greet
    // #[arg(short, long, default_value_t = 1)]
    // pub count: u8,
    // #[arg(short, long)]
    // pub download: bool,
}

}