<script>
  import { onMount } from "svelte";
  import * as api from "./lib/api.js";

  // State
  let view = "welcome"; // welcome | wallet | import | backup
  let wallet = null;
  let balance = null;
  let mnemonic = "";
  let bip39Words = "";
  let importInput = "";
  let importMode = "hex"; // hex | bip39
  let signInput = "";
  let signResult = "";
  let error = "";
  let loading = false;
  let testnet = true;

  // Node connection
  let nodeUrl = "http://localhost:8545";
  let connected = false;
  let chainHeight = 0;
  let sqlInput = "";
  let sqlResult = "";
  let mpcFunc = "sum";
  let mpcTable = "users";
  let mpcColumn = "balance";
  let mpcResult = "";
  let zkTable = "users";
  let zkStatement = "balance > 500";
  let zkResult = "";

  // DEX
  let dexPairBase = "GOLD";
  let dexPairQuote = "SEAL";
  let dexOrderPair = "GOLD/SEAL";
  let dexOrderSide = "bid";
  let dexOrderPrice = "";
  let dexOrderQty = "";
  let dexResult = "";
  let dexPairs = [];
  let dexOrderBook = null;

  // --- Actions ---

  async function createWallet() {
    loading = true;
    error = "";
    try {
      wallet = await api.createWallet(testnet);
      balance = await api.getBalance();
      view = "wallet";
    } catch (e) {
      error = e.toString();
    }
    loading = false;
  }

  async function importWallet() {
    loading = true;
    error = "";
    try {
      if (importMode === "bip39") {
        wallet = await api.importWalletBip39(importInput, testnet);
      } else {
        wallet = await api.importWallet(importInput, testnet);
      }
      balance = await api.getBalance();
      view = "wallet";
    } catch (e) {
      error = e.toString();
    }
    loading = false;
  }

  async function showBackup() {
    try {
      mnemonic = await api.exportMnemonic();
      bip39Words = await api.exportMnemonicBip39();
      view = "backup";
    } catch (e) {
      error = e.toString();
    }
  }

  async function signMessage() {
    if (!signInput) return;
    try {
      const sig = await api.signMessage(signInput);
      signResult = sig.slice(0, 64) + "... (" + (sig.length / 2) + " bytes)";
    } catch (e) {
      error = e.toString();
    }
  }

  async function connectNode() {
    error = "";
    try {
      const resp = await api.rpcGetHeight(nodeUrl);
      const data = JSON.parse(resp);
      if (data.result) {
        chainHeight = data.result.height;
        connected = true;
      } else if (data.error) {
        error = data.error.message || data.error;
      }
    } catch (e) {
      error = "Connection failed: " + e.toString();
    }
  }

  async function runQuery() {
    if (!sqlInput) return;
    error = "";
    try {
      const isWrite = /^(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)/i.test(sqlInput.trim());
      let resp;
      if (isWrite) {
        resp = await api.rpcSend(nodeUrl, sqlInput);
      } else {
        resp = await api.rpcQuery(nodeUrl, sqlInput);
      }
      const data = JSON.parse(resp);
      if (data.result) {
        sqlResult = JSON.stringify(data.result, null, 2);
      } else if (data.error) {
        sqlResult = "Error: " + (data.error.message || JSON.stringify(data.error));
      }
    } catch (e) {
      sqlResult = "Error: " + e.toString();
    }
  }

  async function runMpc() {
    error = "";
    try {
      const resp = await api.rpcMpc(nodeUrl, mpcFunc, mpcTable, mpcColumn);
      const data = JSON.parse(resp);
      if (data.result) {
        mpcResult = `${mpcFunc}(${mpcTable}.${mpcColumn}) = ${data.result.result} (${data.result.row_count} rows)`;
      } else if (data.error) {
        mpcResult = "Error: " + (data.error.message || JSON.stringify(data.error));
      }
    } catch (e) {
      mpcResult = "Error: " + e.toString();
    }
  }

  async function runZk() {
    error = "";
    try {
      const resp = await api.rpcZkProve(nodeUrl, zkTable, zkStatement);
      const data = JSON.parse(resp);
      if (data.result) {
        const s = data.result.satisfied ? "YES" : "NO";
        const proof = data.result.proof || "";
        zkResult = `Satisfied: ${s}\nProof: ${proof.slice(0, 32)}...${proof.slice(-16)}`;
      } else if (data.error) {
        zkResult = "Error: " + (data.error.message || JSON.stringify(data.error));
      }
    } catch (e) {
      zkResult = "Error: " + e.toString();
    }
  }

  async function createPair() {
    error = "";
    try {
      const resp = await api.rpcCreatePair(nodeUrl, dexPairBase, dexPairQuote);
      const data = JSON.parse(resp);
      if (data.result) {
        dexResult = `Pair created: ${dexPairBase}/${dexPairQuote}`;
        await loadPairs();
      } else if (data.error) {
        dexResult = "Error: " + (data.error.message || JSON.stringify(data.error));
      }
    } catch (e) { dexResult = "Error: " + e.toString(); }
  }

  async function placeOrder() {
    error = "";
    try {
      const resp = await api.rpcPlaceOrder(nodeUrl, dexOrderPair, dexOrderSide, Number(dexOrderPrice), Number(dexOrderQty));
      const data = JSON.parse(resp);
      if (data.result) {
        dexResult = `Order #${data.result.order_id} placed (${data.result.trades} trades)`;
      } else if (data.error) {
        dexResult = "Error: " + (data.error.message || JSON.stringify(data.error));
      }
    } catch (e) { dexResult = "Error: " + e.toString(); }
  }

  async function loadPairs() {
    try {
      const resp = await api.rpcListPairs(nodeUrl);
      const data = JSON.parse(resp);
      if (data.result) dexPairs = data.result.pairs || [];
    } catch (e) { /* ignore */ }
  }

  async function loadOrderBook() {
    try {
      const resp = await api.rpcGetOrderBook(nodeUrl, dexOrderPair);
      const data = JSON.parse(resp);
      if (data.result) dexOrderBook = data.result;
      else if (data.error) dexResult = "Error: " + (data.error.message || JSON.stringify(data.error));
    } catch (e) { dexResult = "Error: " + e.toString(); }
  }

  function truncateAddress(addr) {
    if (!addr || addr.length < 20) return addr;
    return addr.slice(0, 12) + "..." + addr.slice(-8);
  }

  function formatBalance(amount) {
    return (amount / 1_000_000_000).toFixed(4);
  }
</script>

<main>
  <header>
    <h1>Seal Wallet</h1>
    <span class="badge">{testnet ? "TESTNET" : "MAINNET"}</span>
  </header>

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <!-- Welcome screen -->
  {#if view === "welcome"}
    <div class="card center">
      <h2>Post-Quantum Secure Wallet</h2>
      <p class="dim">ML-DSA-65 signatures, SHA3-256 hashing, Bech32m addresses</p>

      <div class="actions">
        <button class="primary" on:click={createWallet} disabled={loading}>
          {loading ? "Creating..." : "Create New Wallet"}
        </button>
        <button class="secondary" on:click={() => (view = "import")}>
          Import Existing Wallet
        </button>
      </div>

      <label class="toggle">
        <input type="checkbox" bind:checked={testnet} />
        Testnet mode (sealt1... addresses)
      </label>
    </div>

  <!-- Import screen -->
  {:else if view === "import"}
    <div class="card">
      <h2>Import Wallet</h2>

      <div class="tabs">
        <button class:active={importMode === "hex"} on:click={() => (importMode = "hex")}>
          Hex Seed
        </button>
        <button class:active={importMode === "bip39"} on:click={() => (importMode = "bip39")}>
          BIP-39 Words
        </button>
      </div>

      {#if importMode === "hex"}
        <input
          type="text"
          placeholder="64-character hex seed"
          bind:value={importInput}
          maxlength="64"
        />
      {:else}
        <textarea
          placeholder="Enter 24 BIP-39 words separated by spaces"
          bind:value={importInput}
          rows="3"
        ></textarea>
      {/if}

      <div class="actions">
        <button class="primary" on:click={importWallet} disabled={loading || !importInput}>
          {loading ? "Importing..." : "Import"}
        </button>
        <button class="secondary" on:click={() => (view = "welcome")}>Back</button>
      </div>
    </div>

  <!-- Wallet dashboard -->
  {:else if view === "wallet"}
    <div class="card">
      <h2>Address</h2>
      <div class="address" title={wallet?.seal_address}>
        {wallet?.seal_address || "..."}
      </div>
    </div>

    <div class="card">
      <h2>Balances</h2>
      <div class="balance-grid">
        <div class="balance-item">
          <span class="token">SEAL</span>
          <span class="amount">{balance ? formatBalance(balance.seal) : "0"}</span>
        </div>
        <div class="balance-item">
          <span class="token">wSOL</span>
          <span class="amount">{balance ? formatBalance(balance.wSOL) : "0"}</span>
        </div>
        <div class="balance-item">
          <span class="token">wXLM</span>
          <span class="amount">{balance ? formatBalance(balance.wXLM) : "0"}</span>
        </div>
        <div class="balance-item">
          <span class="token">wUSDC</span>
          <span class="amount">{balance ? formatBalance(balance.wUSDC) : "0"}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>Sign Message</h2>
      <input type="text" placeholder="Enter message to sign" bind:value={signInput} />
      <button class="primary small" on:click={signMessage} disabled={!signInput}>Sign</button>
      {#if signResult}
        <div class="mono dim">{signResult}</div>
      {/if}
    </div>

    <div class="card">
      <h2>Node Connection</h2>
      <div style="display:flex;gap:8px">
        <input type="text" bind:value={nodeUrl} placeholder="http://localhost:8545" style="flex:1" />
        <button class="primary small" on:click={connectNode}>
          {connected ? "Reconnect" : "Connect"}
        </button>
      </div>
      {#if connected}
        <div class="dim" style="margin-top:8px">Connected — height: {chainHeight}</div>
      {/if}
    </div>

    {#if connected}
    <div class="card">
      <h2>SQL Query</h2>
      <input type="text" bind:value={sqlInput} placeholder="SELECT * FROM users" />
      <button class="primary small" on:click={runQuery} disabled={!sqlInput}>Execute</button>
      {#if sqlResult}
        <pre class="mono dim" style="margin-top:8px;background:var(--bg);padding:12px;border-radius:8px;overflow-x:auto;white-space:pre-wrap">{sqlResult}</pre>
      {/if}
    </div>

    <div class="card">
      <h2>MPC Aggregate</h2>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <select bind:value={mpcFunc} style="background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:6px">
          <option value="sum">SUM</option>
          <option value="count">COUNT</option>
          <option value="avg">AVG</option>
        </select>
        <input type="text" bind:value={mpcTable} placeholder="table" style="flex:1" />
        <input type="text" bind:value={mpcColumn} placeholder="column" style="flex:1" />
      </div>
      <button class="primary small" on:click={runMpc}>Run</button>
      {#if mpcResult}
        <div class="mono dim" style="margin-top:8px">{mpcResult}</div>
      {/if}
    </div>

    <div class="card">
      <h2>ZK Proof</h2>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <input type="text" bind:value={zkTable} placeholder="table" style="width:120px" />
        <input type="text" bind:value={zkStatement} placeholder="balance > 500" style="flex:1" />
      </div>
      <button class="primary small" on:click={runZk}>Prove</button>
      {#if zkResult}
        <pre class="mono dim" style="margin-top:8px;background:var(--bg);padding:12px;border-radius:8px;white-space:pre-wrap">{zkResult}</pre>
      {/if}
    </div>

    <div class="card">
      <h2>DEX</h2>
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <input type="text" bind:value={dexPairBase} placeholder="BASE" style="width:80px" />
        <span style="align-self:center">/</span>
        <input type="text" bind:value={dexPairQuote} placeholder="QUOTE" style="width:80px" />
        <button class="primary small" on:click={createPair}>Create Pair</button>
        <button class="secondary small" on:click={loadPairs}>List</button>
      </div>
      {#if dexPairs.length > 0}
        <div class="dim" style="margin-bottom:8px">Pairs: {dexPairs.join(", ")}</div>
      {/if}
      <div style="display:flex;gap:8px;margin-bottom:8px">
        <input type="text" bind:value={dexOrderPair} placeholder="GOLD/SEAL" style="width:120px" />
        <select bind:value={dexOrderSide} style="background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:6px">
          <option value="bid">BID</option>
          <option value="ask">ASK</option>
        </select>
        <input type="text" bind:value={dexOrderPrice} placeholder="price" style="width:80px" />
        <input type="text" bind:value={dexOrderQty} placeholder="qty" style="width:80px" />
      </div>
      <div style="display:flex;gap:8px">
        <button class="primary small" on:click={placeOrder} disabled={!dexOrderPrice || !dexOrderQty}>Place Order</button>
        <button class="secondary small" on:click={loadOrderBook}>Order Book</button>
      </div>
      {#if dexOrderBook}
        <div style="margin-top:8px;display:flex;gap:16px">
          <div style="flex:1">
            <div class="dim">BIDS</div>
            {#each dexOrderBook.bids || [] as b}
              <div class="mono">{b.quantity} @ {b.price}</div>
            {:else}
              <div class="dim">empty</div>
            {/each}
          </div>
          <div style="flex:1">
            <div class="dim">ASKS</div>
            {#each dexOrderBook.asks || [] as a}
              <div class="mono">{a.quantity} @ {a.price}</div>
            {:else}
              <div class="dim">empty</div>
            {/each}
          </div>
        </div>
      {/if}
      {#if dexResult}
        <div class="mono dim" style="margin-top:8px">{dexResult}</div>
      {/if}
    </div>
    {/if}

    <div class="card">
      <h2>Keys</h2>
      <div class="key-info">
        <div><span class="label">ML-DSA Public Key:</span></div>
        <div class="mono dim">
          {wallet?.seal_pubkey_hex?.slice(0, 32)}...
        </div>
        <div><span class="label">Ed25519 Seed (Solana/Stellar):</span></div>
        <div class="mono dim">{wallet?.ed25519_pubkey_hex}</div>
      </div>
    </div>

    <div class="actions">
      <button class="secondary" on:click={showBackup}>Backup Seed</button>
      <button class="secondary" on:click={() => { wallet = null; view = "welcome"; }}>
        Lock Wallet
      </button>
    </div>

  <!-- Backup screen -->
  {:else if view === "backup"}
    <div class="card warning-card">
      <h2>Backup Your Seed</h2>
      <p class="warning">Write this down and store it safely. Anyone with this seed controls your wallet.</p>

      <h3>Hex Seed (64 chars)</h3>
      <div class="mono seed">{mnemonic}</div>

      <h3>BIP-39 Words (24 words)</h3>
      <div class="mono seed">{bip39Words}</div>

      <button class="primary" on:click={() => (view = "wallet")}>Done</button>
    </div>
  {/if}

  <footer>
    <span class="dim">Seal DAO Wallet v0.1.0 | PQC: ML-DSA-65 + SHA3-256</span>
  </footer>
</main>

<style>
  main {
    max-width: 480px;
    margin: 0 auto;
    padding: 20px;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
  }

  header h1 {
    font-size: 1.5rem;
    font-weight: 700;
  }

  .badge {
    background: var(--accent);
    color: white;
    font-size: 0.7rem;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    letter-spacing: 0.5px;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
  }

  .card h2 {
    font-size: 0.9rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
  }

  .card h3 {
    font-size: 0.85rem;
    color: var(--text-dim);
    margin: 16px 0 8px;
  }

  .center { text-align: center; }

  .dim { color: var(--text-dim); font-size: 0.85rem; }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; word-break: break-all; }

  .address {
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.85rem;
    word-break: break-all;
    color: var(--accent);
    user-select: all;
  }

  .seed {
    background: var(--bg);
    padding: 12px;
    border-radius: 8px;
    word-break: break-all;
    user-select: all;
  }

  .balance-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .balance-item {
    display: flex;
    justify-content: space-between;
    padding: 8px 12px;
    background: var(--bg);
    border-radius: 8px;
  }

  .token { font-weight: 600; }
  .amount { color: var(--text-dim); }

  .key-info { display: flex; flex-direction: column; gap: 4px; }
  .label { font-size: 0.8rem; color: var(--text-dim); }

  .actions {
    display: flex; gap: 12px; margin-top: 16px;
    flex-wrap: wrap; justify-content: center;
  }

  button {
    padding: 10px 20px;
    border: none;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }

  button.primary {
    background: var(--accent);
    color: white;
  }
  button.primary:hover { background: var(--accent-hover); }
  button.primary:disabled { opacity: 0.5; cursor: not-allowed; }

  button.secondary {
    background: var(--border);
    color: var(--text);
  }
  button.secondary:hover { background: #3a3a4a; }

  button.small { padding: 6px 14px; font-size: 0.8rem; margin-top: 8px; }

  .tabs { display: flex; gap: 8px; margin-bottom: 12px; }
  .tabs button { padding: 6px 14px; font-size: 0.8rem; background: var(--border); color: var(--text-dim); }
  .tabs button.active { background: var(--accent); color: white; }

  input, textarea {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 14px;
    color: var(--text);
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.85rem;
    margin-bottom: 8px;
  }
  input:focus, textarea:focus { border-color: var(--accent); outline: none; }

  .toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-top: 16px;
    font-size: 0.85rem;
    color: var(--text-dim);
    justify-content: center;
  }

  .error {
    background: #2d1515;
    border: 1px solid var(--error);
    color: var(--error);
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 0.85rem;
  }

  .warning-card { border-color: var(--warning); }
  .warning { color: var(--warning); font-size: 0.85rem; margin-bottom: 12px; }

  footer {
    margin-top: auto;
    padding: 16px 0;
    text-align: center;
  }
</style>
