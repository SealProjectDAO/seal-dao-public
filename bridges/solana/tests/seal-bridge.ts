import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SealBridge } from "../target/types/seal_bridge";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
} from "@solana/spl-token";
import { assert } from "chai";

/**
 * Seal DAO <-> Solana Bridge — Test Scaffold
 *
 * SKELETON: These tests exercise the basic program flow.
 * Real integration tests need a running Seal DAO testnet
 * and relayer infrastructure.
 */
describe("seal-bridge", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.SealBridge as Program<SealBridge>;
  const authority = provider.wallet;

  let mint: anchor.web3.PublicKey;
  let vaultTokenAccount: anchor.web3.PublicKey;
  let senderTokenAccount: anchor.web3.PublicKey;
  let recipientTokenAccount: anchor.web3.PublicKey;
  let bridgeStatePda: anchor.web3.PublicKey;
  let bridgeStateBump: number;

  // A dummy 32-byte Seal DAO address for testing
  const sealAddress = new Uint8Array(32).fill(0xab);

  before(async () => {
    // Derive bridge state PDA
    [bridgeStatePda, bridgeStateBump] =
      anchor.web3.PublicKey.findProgramAddressSync(
        [Buffer.from("bridge_state")],
        program.programId
      );

    // TODO: Create SPL mint, vault account, sender account, recipient account
    // These require the bridge to be initialized first in a real test flow.
    //
    // mint = await createMint(
    //   provider.connection,
    //   authority.payer,
    //   authority.publicKey,
    //   null,
    //   9
    // );
    //
    // vaultTokenAccount = await createAccount(
    //   provider.connection,
    //   authority.payer,
    //   mint,
    //   bridgeStatePda
    // );
    //
    // senderTokenAccount = await createAccount(
    //   provider.connection,
    //   authority.payer,
    //   mint,
    //   authority.publicKey
    // );
    //
    // recipientTokenAccount = await createAccount(
    //   provider.connection,
    //   authority.payer,
    //   mint,
    //   authority.publicKey
    // );
    //
    // // Mint some test tokens to sender
    // await mintTo(
    //   provider.connection,
    //   authority.payer,
    //   mint,
    //   senderTokenAccount,
    //   authority.publicKey,
    //   1_000_000_000 // 1 token with 9 decimals
    // );
  });

  // Shared committee key — in production this matches whatever the
  // Seal node cluster broadcasts as the current epoch's committee MAC
  // key. For the test we just pick a fixed 32-byte value.
  const committeeKey = new Uint8Array(32).fill(0x11);

  it("initializes the bridge", async () => {
    const tx = await program.methods
      .initialize(Array.from(committeeKey))
      .accounts({
        bridgeState: bridgeStatePda,
        authority: authority.publicKey,
        systemProgram: anchor.web3.SystemProgram.programId,
      })
      .rpc();

    console.log("Initialize tx:", tx);

    const state = await program.account.bridgeState.fetch(bridgeStatePda);
    assert.ok(state.authority.equals(authority.publicKey));
    assert.equal(state.totalLocked.toNumber(), 0);
    assert.equal(state.nonce.toNumber(), 0);
    assert.deepEqual(Array.from(state.committeeKey), Array.from(committeeKey));
  });

  it("rotates the committee key", async () => {
    const newKey = new Uint8Array(32).fill(0x22);
    await program.methods
      .rotateCommitteeKey(Array.from(newKey))
      .accounts({
        bridgeState: bridgeStatePda,
        authority: authority.publicKey,
      })
      .rpc();
    const state = await program.account.bridgeState.fetch(bridgeStatePda);
    assert.deepEqual(Array.from(state.committeeKey), Array.from(newKey));

    // Rotate back so subsequent tests can use the original key.
    await program.methods
      .rotateCommitteeKey(Array.from(committeeKey))
      .accounts({
        bridgeState: bridgeStatePda,
        authority: authority.publicKey,
      })
      .rpc();
  });

  it("locks tokens into the bridge", async () => {
    // TODO: Uncomment and complete once SPL token accounts are set up above.
    //
    // const lockAmount = new anchor.BN(500_000_000); // 0.5 tokens
    //
    // // Derive lock record PDA
    // const state = await program.account.bridgeState.fetch(bridgeStatePda);
    // const [lockRecordPda] = anchor.web3.PublicKey.findProgramAddressSync(
    //   [
    //     Buffer.from("lock_record"),
    //     state.nonce.toArrayLike(Buffer, "le", 8),
    //   ],
    //   program.programId
    // );
    //
    // const tx = await program.methods
    //   .lockTokens(lockAmount, Array.from(sealAddress))
    //   .accounts({
    //     bridgeState: bridgeStatePda,
    //     lockRecord: lockRecordPda,
    //     sender: authority.publicKey,
    //     senderTokenAccount: senderTokenAccount,
    //     vaultTokenAccount: vaultTokenAccount,
    //     tokenProgram: TOKEN_PROGRAM_ID,
    //     systemProgram: anchor.web3.SystemProgram.programId,
    //   })
    //   .rpc();
    //
    // console.log("Lock tx:", tx);
    //
    // const updatedState = await program.account.bridgeState.fetch(bridgeStatePda);
    // assert.equal(updatedState.totalLocked.toNumber(), 500_000_000);
    // assert.equal(updatedState.nonce.toNumber(), 1);
    //
    // const record = await program.account.lockRecord.fetch(lockRecordPda);
    // assert.equal(record.amount.toNumber(), 500_000_000);
    // assert.deepEqual(Array.from(record.sealAddress), Array.from(sealAddress));

    console.log("SKIP: lock_tokens test — SPL token setup not yet wired");
  });

  it("unlocks tokens from the bridge", async () => {
    // TODO: Uncomment and complete once lock_tokens test is working.
    //
    // const unlockAmount = new anchor.BN(250_000_000); // 0.25 tokens
    // const nonce = new anchor.BN(0);
    //
    // // TODO: Replace with real Ringtail/ML-DSA threshold signature
    // const dummySignature = Buffer.from([0x01, 0x02, 0x03, 0x04]);
    //
    // const tx = await program.methods
    //   .unlockTokens(unlockAmount, nonce, dummySignature)
    //   .accounts({
    //     bridgeState: bridgeStatePda,
    //     authority: authority.publicKey,
    //     recipient: authority.publicKey,
    //     recipientTokenAccount: recipientTokenAccount,
    //     vaultTokenAccount: vaultTokenAccount,
    //     tokenProgram: TOKEN_PROGRAM_ID,
    //   })
    //   .rpc();
    //
    // console.log("Unlock tx:", tx);
    //
    // const updatedState = await program.account.bridgeState.fetch(bridgeStatePda);
    // assert.equal(updatedState.totalLocked.toNumber(), 250_000_000);

    console.log("SKIP: unlock_tokens test — depends on lock_tokens");
  });

  it("rejects empty signature on unlock", async () => {
    // TODO: Uncomment once token accounts are set up.
    //
    // const unlockAmount = new anchor.BN(100_000_000);
    // const nonce = new anchor.BN(99);
    // const emptySignature = Buffer.alloc(0);
    //
    // try {
    //   await program.methods
    //     .unlockTokens(unlockAmount, nonce, emptySignature)
    //     .accounts({
    //       bridgeState: bridgeStatePda,
    //       authority: authority.publicKey,
    //       recipient: authority.publicKey,
    //       recipientTokenAccount: recipientTokenAccount,
    //       vaultTokenAccount: vaultTokenAccount,
    //       tokenProgram: TOKEN_PROGRAM_ID,
    //     })
    //     .rpc();
    //   assert.fail("Expected InvalidSignature error");
    // } catch (err) {
    //   assert.include(err.toString(), "InvalidSignature");
    // }

    console.log("SKIP: reject-empty-signature test — depends on token setup");
  });
});
