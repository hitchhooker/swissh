// types.rs
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "upper")]
pub enum AssetType {
    Dot, // native
    //Ibtc = 1986,
    Usdc = 1337,
    Usdt = 1984,
    Rnet = 181,
}

impl AssetType {
    pub fn decimals(&self) -> u32 {
        match self {
            AssetType::Dot => 10,
            AssetType::Usdt | AssetType::Usdc => 6,
//            AssetType::Ibtc => 8,
            AssetType::Rnet => 12,
        }
    }
    pub fn on_chain_id(&self) -> u32 {
        self.clone() as u32
    }
}
