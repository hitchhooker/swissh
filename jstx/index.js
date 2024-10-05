const { ApiPromise, WsProvider, Keyring } = require('@polkadot/api');
const { hexToU8a, BN } = require('@polkadot/util');

async function main() {
  const provider = new WsProvider('wss://rpc.rotko.net/polkadot');
  const api = await ApiPromise.create({ provider });
  const keyring = new Keyring({ type: 'ed25519' });

  const privateKeyHex = '0xea59c3e2663897c043ef0fdcb26b4bdbff51c7abddfa88b183f12461f8ce8993';
  const sender = keyring.addFromSeed(hexToU8a(privateKeyHex));

  console.log(`Sender SS58 Address: ${sender.address}`);

  const { data: balance } = await api.query.system.account(sender.address);
  console.log(`Current balance: ${balance.free.toString()}`);

  const extrinsic = api.tx.balances.transferAll('14tomgoLTmCspokR9jDnqPsY4PaNGzCRwDLH5sRAdaN5jd96', false);

  const signed = await extrinsic.signAsync(sender);
  console.log(`Signed transaction: ${signed.toHex()}`);
}

main().catch(console.error).finally(() => process.exit());
