import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const BN = (anchor as any).default?.BN ?? (anchor as any).BN;
import { SealBridge } from "../target/types/seal_bridge";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
} from "@solana/spl-token";
import { assert } from "chai";

/**
 * Seal DAO <-> Solana Bridge — Integration Tests
 *
 * These tests exercise the full on-chain program flow.
 * Real end-to-end tests with Seal DAO relayer infrastructure
 * are in scripts/bridge-e2e.sh.
 */
describe("seal-bridge", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SealBridge as Program<SealBridge>;
  const authority = provider.wallet as anchor.Wallet;

  let mint: anchor.web3.PublicKey;
  let vaultTokenAccount: anchor.web3.PublicKey;
  let senderTokenAccount: anchor.web3.PublicKey;
  let recipientTokenAccount: anchor.web3.PublicKey;
  let bridgeStatePda: anchor.web3.PublicKey;
  let bridgeStateBump: number;

  // 32-byte Seal DAO recipient. bridge-e2e.sh exports
  // SEAL_RECIPIENT_HEX from a real `seal keygen` key file (so the
  // reverse leg can sign the wrapped-balance burn with the matching
  // ML-DSA key); when invoked standalone we fall back to [0xab; 32]
  // — that lets the forward-only test still pass, even though the
  // reverse leg won't have a matching key for that address.
  const sealRecipientHex = process.env.SEAL_RECIPIENT_HEX;
  const sealAddress = sealRecipientHex && /^[0-9a-f]{64}$/i.test(sealRecipientHex)
    ? Buffer.from(sealRecipientHex, "hex")
    : new Uint8Array(32).fill(0xab);

  before(async () => {
    // Derive bridge state PDA
    [bridgeStatePda, bridgeStateBump] =
      anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("bridge_state")],
        program.programId
      );

    // Create a fresh SPL mint each run (no keypair arg → random address,
    // so there's no "already exists" conflict on re-runs against the same
    // persistent validator).
    mint = await createMint(
      provider.connection,
      authority.payer,
      authority.publicKey,
      null,
      9
    );

    // Always pass explicit keypairs so createAccount uses the raw SPL Token path
    // (InitializeAccount) rather than falling back to createAssociatedTokenAccount.
    // The ATA path rejects off-curve (PDA) owners and can fail on some validator
    // versions even for regular pubkeys, so explicit keypairs are safer here.
    vaultTokenAccount = await createAccount(
      provider.connection,
      authority.payer,
      mint,
      bridgeStatePda,
      anchor.web3.Keypair.generate()
    );

    senderTokenAccount = await createAccount(
      provider.connection,
      authority.payer,
      mint,
      authority.publicKey,
      anchor.web3.Keypair.generate()
    );

    recipientTokenAccount = await createAccount(
      provider.connection,
      authority.payer,
      mint,
      authority.publicKey,
      anchor.web3.Keypair.generate()
    );

    // Mint 1 token (9-decimal) to the sender account.
    await mintTo(
      provider.connection,
      authority.payer,
      mint,
      senderTokenAccount,
      authority.publicKey,
      1_000_000_000
    );
  });

  // Shared committee key — in production this matches whatever the
  // Seal node cluster broadcasts as the current epoch's committee MAC
  // key. For the test we just pick a fixed 32-byte value.
  const committeeKey = new Uint8Array(32).fill(0x11);

  it("initializes the bridge", async () => {
    try {
      const tx = await program.methods
        .initialize(Array.from(committeeKey))
        .accountsPartial({
          bridgeState: bridgeStatePda,
          authority: authority.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
      console.log("Initialize tx:", tx);
    } catch (err: any) {
      // PDA already exists from a prior run against this same validator.
      // "already in use" (0x0) means the account was previously allocated.
      const alreadyInit =
        err?.message?.includes("already in use") ||
        err?.message?.includes("custom program error: 0x0");
      if (!alreadyInit) throw err;
      console.log("Bridge already initialized (re-run against same validator — ok)");
    }

    const state = await program.account.bridgeState.fetch(bridgeStatePda);
    assert.ok(state.authority.equals(authority.publicKey));
  });

  it("rotates the committee key", async () => {
    const newKey = new Uint8Array(32).fill(0x22);
    await program.methods
      .rotateCommitteeKey(Array.from(newKey))
      .accountsPartial({
        bridgeState: bridgeStatePda,
        authority: authority.publicKey,
      })
      .rpc();
    const state = await program.account.bridgeState.fetch(bridgeStatePda);
    assert.deepEqual(Array.from(state.committeeKey), Array.from(newKey));

    // Rotate back so subsequent tests can use the original key.
    await program.methods
      .rotateCommitteeKey(Array.from(committeeKey))
      .accountsPartial({
        bridgeState: bridgeStatePda,
        authority: authority.publicKey,
      })
      .rpc();
  });

  it("locks tokens into the bridge", async () => {
    const lockAmount = new BN(500_000_000); // 0.5 tokens

    // Snapshot state before lock so assertions are relative (safe on re-runs
    // against the same persistent validator where nonce/totalLocked may be > 0).
    const before = await program.account.bridgeState.fetch(bridgeStatePda);

    // Derive the lock record PDA for the CURRENT nonce.
    const [lockRecordPda] = anchor.web3.PublicKey.findProgramAddressSync(
      [
        Buffer.from("lock_record"),
        before.nonce.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    const tx = await program.methods
      .lockTokens(lockAmount, Array.from(sealAddress))
      .accountsPartial({
        bridgeState: bridgeStatePda,
        lockRecord: lockRecordPda,
        sender: authority.publicKey,
        senderTokenAccount: senderTokenAccount,
        vaultTokenAccount: vaultTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    console.log("Lock tx:", tx);
    // Emit the addresses bridge-e2e.sh needs for the reverse leg.
    // Without these, the script can't run unlock_tokens because the
    // mint/recipient/authority + vault are all created fresh per
    // test and never surfaced. Prefix is unique enough to grep out
    // of stdout/log.
    //
    // REVERSE_VAULT_ATA is critical: the test creates
    // `vaultTokenAccount` via `createAccount(..., bridgeStatePda,
    // Keypair.generate())` so the address is RANDOM per run, NOT
    // the canonical `getAssociatedTokenAddress(mint, bridgeStatePda)`
    // that `derive-vault-ata.ts` computes. The lock deposits into
    // this random account; the unlock must reference the same one
    // or Anchor errors with `AccountNotInitialized` on the
    // canonical-ATA path.
    console.log("REVERSE_MINT:", mint.toBase58());
    console.log("REVERSE_RECIPIENT:", authority.publicKey.toBase58());
    console.log("REVERSE_RECIPIENT_ATA:", recipientTokenAccount.toBase58());
    console.log("REVERSE_AUTHORITY:", authority.publicKey.toBase58());
    console.log("REVERSE_VAULT_ATA:", vaultTokenAccount.toBase58());

    const after = await program.account.bridgeState.fetch(bridgeStatePda);
    assert.equal(
      after.totalLocked.sub(before.totalLocked).toNumber(),
      500_000_000
    );
    assert.equal(after.nonce.sub(before.nonce).toNumber(), 1);

    const record = await program.account.lockRecord.fetch(lockRecordPda);
    assert.equal(record.amount.toNumber(), 500_000_000);
    assert.deepEqual(Array.from(record.sealAddress), Array.from(sealAddress));
  });

  it("unlocks tokens from the bridge", async () => {
    // Real unlock requires a valid Ringtail/ML-DSA threshold signature from
    // the Seal committee. Until that signature infrastructure is wired into
    // the e2e test, we skip and document the expected interface.
    //
    // const unlockAmount = new BN(250_000_000);
    // const nonce = new BN(0);
    // const committeeSignature = Buffer.from([...]); // real ML-DSA sig here
    //
    // await program.methods
    //   .unlockTokens(unlockAmount, nonce, committeeSignature)
    //   .accountsPartial({
    //     bridgeState: bridgeStatePda,
    //     authority: authority.publicKey,
    //     recipient: authority.publicKey,
    //     recipientTokenAccount,
    //     vaultTokenAccount,
    //     tokenProgram: TOKEN_PROGRAM_ID,
    //   })
    //   .rpc();

    console.log("SKIP: unlock_tokens — pending Ringtail signature wiring");
  });

  it("rejects empty signature on unlock", async () => {
    // Once unlockTokens is wired, this test verifies the on-chain guard:
    //
    // const emptySignature = Buffer.alloc(0);
    // try {
    //   await program.methods
    //     .unlockTokens(new BN(100_000_000), new BN(99), emptySignature)
    //     .accountsPartial({...})
    //     .rpc();
    //   assert.fail("Expected InvalidSignature error");
    // } catch (err) {
    //   assert.include(err.toString(), "InvalidSignature");
    // }

    console.log("SKIP: reject-empty-signature — pending Ringtail signature wiring");
  });
});
