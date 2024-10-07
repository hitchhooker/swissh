// types.rs
use clap::ValueEnum;

#[derive(Debug, Clone, ValueEnum)]
#[clap(rename_all = "upper")]
pub enum AssetType {
    Dot, // native
    Ibtc = 1986,
    Rnet = 181,
    Usdc = 1337,
    Usdt = 1984,
}
