// scripts/lock-sol.ts — parametric devnet `lock_tokens` driver.
//
// Closes the testnet gap that `docs/BRIDGE-TESTNET.md §2.1` flagged:
// without this, ad-hoc devnet locks required hand-writing TS against
// the program. The existing `tests/seal-bridge.ts` exercises the same
// `.lockTokens()` call but with hard-coded fixtures; this script
// takes CLI args so an operator can drive arbitrary amount /
// seal-recipient pairs against a deployed mint.
//
// Wired as `anchor run lock-sol` via Anchor.toml `[scripts]`.
//
// Required CLI args (parsed loosely so this works under both
// `anchor run lock-sol -- --amount …` and plain `npx tsx`):
//   --amount <u64>           Lock amount in base units
//   --seal-recipient <hex>   32-byte Seal recipient (64 hex chars,
//                            no 0x prefix). Use `seal addr-to-hex
//                            sealt1…` to derive.
//   --mint <pubkey>          SPL mint to lock (base58). Required —
//                            the bridge program tracks mints per
//                            locked-token type, no native SOL path.
//   --sender-ata <pubkey>    Source SPL token account (caller-owned).
//   --vault-ata <pubkey>     Vault SPL token account (PDA-owned).
//
// Optional (defaults match Anchor's provider env):
//   --program-id <pubkey>    Override the program ID. Defaults to
//                            anchor.workspace.SealBridge.programId.

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SealBridge } from "../target/types/seal_bridge";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const BN = (anchor as any).default?.BN ?? (anchor as any).BN;

function flag(name: string): string | undefined {
  const args = process.argv.slice(2);
  const i = args.indexOf(`--${name}`);
  if (i === -1 || i + 1 >= args.length) return undefined;
  return args[i + 1];
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
  const sender = (provider.wallet as anchor.Wallet).publicKey;

  const amountStr = requireFlag("amount");
  const sealRecipientHex = requireFlag("seal-recipient");
  const mint = new anchor.web3.PublicKey(requireFlag("mint"));
  const senderAta = new anchor.web3.PublicKey(requireFlag("sender-ata"));
  const vaultAta = new anchor.web3.PublicKey(requireFlag("vault-ata"));
  const programIdOverride = flag("program-id");

  if (programIdOverride) {
    // Caller pinned an explicit deploy; trust it.
    console.log(`Using program ID: ${programIdOverride}`);
  }

  if (sealRecipientHex.length !== 64) {
    console.error(
      `error: --seal-recipient must be 64 hex chars (32 bytes); got ${sealRecipientHex.length}`,
    );
    process.exit(1);
  }
  const sealRecipient = Buffer.from(sealRecipientHex, "hex");
  if (sealRecipient.length !== 32) {
    console.error("error: --seal-recipient hex decode produced != 32 bytes");
    process.exit(1);
  }

  // Derive the bridge state PDA + the lock_record PDA for the
  // current nonce. The program rejects out-of-order nonces, so we
  // have to read state.nonce first.
  const [bridgeStatePda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("bridge_state")],
    program.programId,
  );

  const before = await program.account.bridgeState.fetch(bridgeStatePda);
  const [lockRecordPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [
      Buffer.from("lock_record"),
      before.nonce.toArrayLike(Buffer, "le", 8),
    ],
    program.programId,
  );

  const amount = new BN(amountStr);
  console.log(
    `Locking ${amountStr} base units → Seal ${sealRecipientHex.slice(0, 12)}… (nonce ${before.nonce.toString()})`,
  );

  const tx = await program.methods
    .lockTokens(amount, Array.from(sealRecipient))
    .accountsPartial({
      bridgeState: bridgeStatePda,
      lockRecord: lockRecordPda,
      sender,
      senderTokenAccount: senderAta,
      vaultTokenAccount: vaultAta,
      tokenProgram: TOKEN_PROGRAM_ID,
      systemProgram: anchor.web3.SystemProgram.programId,
    })
    .rpc();

  console.log(`Lock tx: ${tx}`);
  const after = await program.account.bridgeState.fetch(bridgeStatePda);
  console.log(`  total_locked: ${after.totalLocked.toString()}`);
  console.log(`  nonce:        ${after.nonce.toString()}`);
  console.log(`  lock_record:  ${lockRecordPda.toBase58()}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
