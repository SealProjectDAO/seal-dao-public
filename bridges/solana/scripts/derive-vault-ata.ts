// scripts/derive-vault-ata.ts — print the bridge vault ATA for a mint.
//
// The seal-bridge Anchor program's `lock_tokens` ix expects the
// caller to pass the vault SPL token account. The canonical choice
// is the Associated Token Account owned by the `bridge_state` PDA —
// that ensures the bridge program itself can sign the eventual
// unlock CPI (the vault is PDA-owned, the PDA's seed is well-known).
//
// Until this script, operators had to compute that ATA by hand. Now
// `anchor run derive-vault-ata -- --mint <mint>` prints
// (bridge_state_pda, vault_ata) so it can be piped into
// `lock-sol`/`lock-usdc`.
//
// Optional `--init` flag funds + creates the ATA if it doesn't
// exist yet — required before the first lock against any new mint.
//
// Wired as `anchor run derive-vault-ata` via Anchor.toml `[scripts]`.
//
// Usage:
//   anchor run derive-vault-ata -- --mint <mint-pubkey>
//   anchor run derive-vault-ata -- --mint <mint-pubkey> --init

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SealBridge } from "../target/types/seal_bridge";
import {
  getAssociatedTokenAddress,
  getOrCreateAssociatedTokenAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

function flag(name: string): string | undefined {
  const args = process.argv.slice(2);
  const i = args.indexOf(`--${name}`);
  if (i === -1 || i + 1 >= args.length) return undefined;
  return args[i + 1];
}

function boolFlag(name: string): boolean {
  return process.argv.slice(2).includes(`--${name}`);
}

function requireFlag(name: string): string {
  const v = flag(name);
  if (!v) {
    console.error(`error: --${name} is required`);
    process.exit(1);
  }
  return v;
}

async function main() {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.SealBridge as Program<SealBridge>;

  const mint = new anchor.web3.PublicKey(requireFlag("mint"));
  const init = boolFlag("init");

  const [bridgeStatePda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("bridge_state")],
    program.programId,
  );

  // `allowOwnerOffCurve=true` because bridge_state is a PDA (not a
  // signer-keypair pubkey on the ed25519 curve). Without this,
  // getAssociatedTokenAddress refuses to derive.
  const vaultAta = await getAssociatedTokenAddress(
    mint,
    bridgeStatePda,
    true,
    TOKEN_PROGRAM_ID,
  );

  console.log(`mint:             ${mint.toBase58()}`);
  console.log(`bridge_state PDA: ${bridgeStatePda.toBase58()}`);
  console.log(`vault ATA:        ${vaultAta.toBase58()}`);

  if (init) {
    // Idempotent — getOrCreate returns the existing account if it's
    // already initialized.
    const payer = (provider.wallet as anchor.Wallet).payer;
    const account = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      payer,
      mint,
      bridgeStatePda,
      true,
    );
    console.log(`vault initialized at ${account.address.toBase58()}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
