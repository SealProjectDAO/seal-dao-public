// scripts/unlock-tokens.ts — parametric `unlock_tokens` driver (k-of-n
// committee member multisig).
//
// Closes the reverse-flow gap on the Solana side. Pairs with the
// `seal bridge-withdraw` → `seal bridge-get-withdrawal` flow on the
// Seal node side: feed the (amount, nonce) the host produced into the
// on-chain `unlock_tokens(amount, nonce)` ix.
//
// **Authorization is a k-of-n committee member multisig** — there is no
// message-level signature in this design. Each committee member holds an
// ed25519 keypair whose *public* key is registered in
// `bridge_state.committee_members`. The unlock tx must be *signed* — as
// native Solana tx signers, verified by the runtime at zero program
// cost — by at least `bridge_state.unlock_threshold` **distinct**
// members. The members' signatures bind the whole tx (recipient, amount,
// nonce), so no separate payload signature is needed. There is no shared
// secret anywhere: forging an unlock needs `threshold`+ members' private
// keys.
//
// This is a single-operator *driver* for devnet / testnet: it loads the
// required member keypairs and co-signs the tx locally, mirroring the
// on-chain E2E. In production each member signs their own copy of the
// same unsigned tx and the relayer aggregates the signatures (that
// per-member path is the node-side seal-bridge signing command) — this
// script holds the member keys only for the single-operator exercise
// flow, exactly as `lock-sol.ts` holds the sender key.
//
// Every unlock nonce is replay-protected on-chain: the ix creates a
// per-nonce `unlockedRecord` PDA (seeds: "unlocked", bridgeState,
// nonce_le(8)) and a second tx at the same nonce is rejected with
// AlreadyProcessed. This script derives that PDA and includes it (plus
// the system program); the authority — the provider wallet, the fee
// payer — pays the record rent.
//
// Wired as `anchor run unlock-tokens` via Anchor.toml `[scripts]`.
//
// Required CLI args (parsed loosely, works under `anchor run … -- …`
// and plain `npx tsx scripts/unlock-tokens.ts …`):
//   --amount <u64>            Unlock amount in base units
//   --nonce <u64>             Nonce from seal_getBridgeWithdrawal
//   --recipient <pubkey>      Solana recipient (matches the withdraw)
//   --recipient-ata <pubkey>  SPL token account that receives the unlock
//   --vault-ata <pubkey>      Vault SPL token account (PDA-owned)
//   --committee-signer <path> Member keypair file (Solana 64-byte JSON
//                             array). Repeatable, 1..8. Each pubkey must
//                             be in bridge_state.committee_members and
//                             the distinct count must be >=
//                             unlock_threshold (checked before send).

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { readFileSync } from "fs";
import { SealBridge } from "../target/types/seal_bridge";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const BN = (anchor as any).default?.BN ?? (anchor as any).BN;
const MAX_SLOTS = 8;

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

/// Collect every `--<name> <value>` occurrence (for repeatable flags).
function flagRepeated(name: string): string[] {
  const args = process.argv.slice(2);
  const out: string[] = [];
  for (let i = 0; i < args.length - 1; i++) {
    if (args[i] === `--${name}`) out.push(args[i + 1]);
  }
  return out;
}

/// Load a Solana keypair from a 64-byte JSON array file.
function loadKeypair(path: string): anchor.web3.Keypair {
  const raw = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(raw) || raw.length !== 64) {
    console.error(`error: ${path} is not a 64-byte Solana keypair JSON array`);
    process.exit(1);
  }
  return anchor.web3.Keypair.fromSecretKey(Uint8Array.from(raw));
}

async function main() {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);
  const program = anchor.workspace.SealBridge as Program<SealBridge>;

  // The relayer (authority) is the provider wallet: it signs, is the fee
  // payer, and pays the unlockedRecord rent.
  const authority = (provider.wallet as anchor.Wallet).publicKey;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const payer = (provider.wallet as any).payer;
  if (!payer) {
    console.error(
      "error: provider wallet has no keypair; set SOLANA_KEYPAIR_PATH / " +
        "ANCHOR_WALLET to the relayer's keypair file",
    );
    process.exit(1);
  }

  const amountStr = requireFlag("amount");
  const nonceStr = requireFlag("nonce");
  const recipient = new anchor.web3.PublicKey(requireFlag("recipient"));
  const recipientAta = new anchor.web3.PublicKey(requireFlag("recipient-ata"));
  const vaultAta = new anchor.web3.PublicKey(requireFlag("vault-ata"));

  const signerPaths = flagRepeated("committee-signer");
  if (signerPaths.length === 0) {
    console.error(
      "error: at least one --committee-signer <keypair-file> is required",
    );
    process.exit(1);
  }
  if (signerPaths.length > MAX_SLOTS) {
    console.error(
      `error: at most ${MAX_SLOTS} --committee-signer entries are allowed`,
    );
    process.exit(1);
  }
  const signers = signerPaths.map((p) => loadKeypair(p));

  const [bridgeStatePda] = anchor.web3.PublicKey.findProgramAddressSync(
    [Buffer.from("bridge_state")],
    program.programId,
  );

  const amount = new BN(amountStr);
  const nonce = new BN(nonceStr);

  // Replay-guard record PDA — must match the program's seeds exactly:
  // [b"unlocked", bridge_state, nonce.to_le_bytes()] (8-byte LE nonce).
  const [unlockedRecordPda] = anchor.web3.PublicKey.findProgramAddressSync(
    [
      Buffer.from("unlocked"),
      bridgeStatePda.toBuffer(),
      nonce.toArrayLike(Buffer, "le", 8),
    ],
    program.programId,
  );

  // Client-side committee check: fail fast (and cheaply) rather than pay
  // for a tx the program would reject with
  // InsufficientCommitteeSignatures.
  const before = await program.account.bridgeState.fetch(bridgeStatePda);
  const memberCount = Number(before.memberCount);
  const threshold = Number(before.unlockThreshold);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registered = (before.committeeMembers as anchor.web3.PublicKey[])
    .slice(0, memberCount)
    .map((p) => p.toBase58());
  const distinct = new Set<string>();
  for (const k of signers) {
    const b58 = k.publicKey.toBase58();
    if (!registered.includes(b58)) {
      console.error(
        `error: committee signer ${b58} is not in bridge_state.committee_members`,
      );
      process.exit(1);
    }
    distinct.add(b58);
  }
  if (distinct.size < threshold) {
    console.error(
      `error: need >= ${threshold} distinct registered member signer(s); ` +
        `got ${distinct.size}`,
    );
    process.exit(1);
  }

  // Fill the 8 committee_signer_N slots: the registered member keys for
  // the co-signers, then the authority (already signed) for the rest.
  const slotNames = [
    "committeeSigner0", "committeeSigner1", "committeeSigner2",
    "committeeSigner3", "committeeSigner4", "committeeSigner5",
    "committeeSigner6", "committeeSigner7",
  ] as const;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const accounts: Record<string, any> = {
    bridgeState: bridgeStatePda,
    authority,
    recipient,
    recipientTokenAccount: recipientAta,
    vaultTokenAccount: vaultAta,
    unlockedRecord: unlockedRecordPda,
    systemProgram: anchor.web3.SystemProgram.programId,
    tokenProgram: TOKEN_PROGRAM_ID,
  };
  signers.forEach((k, i) => {
    accounts[slotNames[i]] = k.publicKey;
  });
  for (let i = signers.length; i < MAX_SLOTS; i++) {
    accounts[slotNames[i]] = authority;
  }

  console.log(
    `Unlocking ${amountStr} → ${recipient.toBase58().slice(0, 8)}… ` +
      `nonce=${nonceStr} (${distinct.size} member signer(s), threshold ${threshold})`,
  );

  const tx = await program.methods
    .unlockTokens(amount, nonce)
    .accountsPartial(accounts)
    .transaction();

  // Fee payer (authority) first, then the member co-signers. Each member
  // pubkey is already a tx account (a committee_signer_N), so its
  // signature binds the whole tx (recipient, amount, nonce included).
  const signature = await provider.sendAndConfirm(tx, [payer, ...signers]);

  console.log(`Unlock tx: ${signature}`);
  const after = await program.account.bridgeState.fetch(bridgeStatePda);
  console.log(`  total_locked: ${after.totalLocked.toString()}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
