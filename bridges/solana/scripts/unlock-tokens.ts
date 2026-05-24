// scripts/unlock-tokens.ts — parametric `unlock_tokens` claim driver.
//
// Closes the reverse-flow gap on the Solana side. Pairs with the
// `seal bridge-withdraw` → `seal bridge-get-withdrawal` flow on the
// Seal node side: feed the (amount, nonce, signature) the host
// produced into the on-chain `unlock_tokens(amount, nonce, signature)`
// ix, which the Anchor program's `verify_committee_sig` recomputes
// HMAC-SHA-256(committee_key, recipient(32) || amount_le(8) ||
// nonce_le(8) || domain_tag) and accepts iff the bytes match.
//
// Wired as `anchor run unlock-tokens` via Anchor.toml `[scripts]`.
//
// Required CLI args:
//   --amount <u64>           Unlock amount in base units
//   --nonce <u64>            Nonce from seal_getBridgeWithdrawal
//   --signature <hex>        committee_signature_hex from
//                            seal_getBridgeWithdrawal (64 hex chars,
//                            i.e. 32 bytes of HMAC-SHA-256)
//   --recipient-ata <pubkey> SPL token account that receives the unlock
//   --vault-ata <pubkey>     Vault SPL token account (PDA-owned)
//   --recipient <pubkey>     Solana recipient pubkey (matches what the
//                            seal-bridge-withdraw was issued for)
//   --authority <pubkey>     Authority signing the unlock (matches
//                            bridge_state.authority set at initialize)

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

  const amountStr = requireFlag("amount");
  const nonceStr = requireFlag("nonce");
  const sigHex = requireFlag("signature").replace(/^0x/, "");
  if (sigHex.length !== 64) {
    console.error(
      `error: --signature must be 64 hex chars (32 bytes); got ${sigHex.length}`,
    );
    process.exit(1);
  }
  const recipient = new anchor.web3.PublicKey(requireFlag("recipient"));
  const recipientAta = new anchor.web3.PublicKey(requireFlag("recipient-ata"));
  const vaultAta = new anchor.web3.PublicKey(requireFlag("vault-ata"));
  const authority = new anchor.web3.PublicKey(requireFlag("authority"));

  const [bridgeStatePda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("bridge_state")],
    program.programId,
  );

  const amount = new BN(amountStr);
  const nonce = new BN(nonceStr);
  const signature = Buffer.from(sigHex, "hex");

  console.log(
    `Unlocking ${amountStr} → ${recipient.toBase58().slice(0, 8)}… nonce=${nonceStr}`,
  );

  const tx = await program.methods
    .unlockTokens(amount, nonce, signature)
    .accountsPartial({
      bridgeState: bridgeStatePda,
      authority,
      recipient,
      recipientTokenAccount: recipientAta,
      vaultTokenAccount: vaultAta,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .rpc();

  console.log(`Unlock tx: ${tx}`);
  const after = await program.account.bridgeState.fetch(bridgeStatePda);
  console.log(`  total_locked: ${after.totalLocked.toString()}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
