// Seal Explorer — vanilla JS, no build step
// Queries the seal-node JSON-RPC endpoint

let rpcUrl = 'http://localhost:8545';
let pollInterval = null;
let lastHeight = 0;

// ── RPC helper ──────────────────────────────────────

async function rpc(method, params = {}) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || JSON.stringify(json.error));
  return json.result;
}

async function fetchStatus() {
  const res = await fetch(rpcUrl + '/status');
  return res.json();
}

// ── Connection ──────────────────────────────────────

async function connect() {
  rpcUrl = document.getElementById('rpc-url').value.replace(/\/$/, '');
  try {
    await refresh();
    setOnline(true);
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(refresh, 2000);
  } catch (e) {
    setOnline(false);
    console.error('Connection failed:', e);
  }
}

function setOnline(online) {
  const dot = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  dot.className = 'dot ' + (online ? 'online' : 'offline');
  text.textContent = online ? 'Connected' : 'Disconnected';
}

// ── Data refresh ────────────────────────────────────

async function refresh() {
  try {
    // Fetch status (includes all overview data)
    const status = await fetchStatus();

    document.getElementById('chain-height').textContent = status.height;
    document.getElementById('chain-epoch').textContent = status.epoch;
    document.getElementById('chain-root').textContent = truncHash(status.state_root);
    document.getElementById('chain-peers').textContent = status.peers;
    document.getElementById('chain-validators').textContent = status.validators;
    document.getElementById('chain-uptime').textContent = formatUptime(status.uptime_secs);

    // Fetch recent blocks (last 10)
    const height = status.height;
    if (height !== lastHeight) {
      lastHeight = height;
      await refreshBlocks(height);
    }

    // Fetch namespaces
    const nsResult = await rpc('seal_getNamespaces');
    renderNamespaces(nsResult.namespaces || []);

    // Tokens — symbol/name/supply/authorities. Cheap call; only
    // re-renders the table when the count or any payload changes.
    await refreshTokens();

    // State-sync snapshots — tiny payload (≤32 entries), refresh
    // each tick so a late-joiner watching the tab sees the roster
    // grow at epoch boundaries.
    await refreshSnapshots();

    // Bridge — committee key state + per-token locked/minted +
    // paused-chain count. Lets explorer viewers see at a glance
    // whether the bridge is healthy (mirrors the /metrics +
    // Grafana surface for non-prometheus consumers).
    await refreshBridge();

    // Refresh DEX pair list + active tape (low cost; pair set
    // changes rarely so the dropdown reorganization is cheap).
    await refreshPairs();
    if (selectedPair) await pollTrades();

    setOnline(true);
  } catch (e) {
    setOnline(false);
    console.error('Refresh failed:', e);
  }
}

async function refreshBlocks(height) {
  const tbody = document.getElementById('block-list');
  tbody.innerHTML = '';

  const start = Math.max(1, height - 9);
  for (let h = height; h >= start; h--) {
    try {
      const block = await rpc('seal_getBlock', { height: h });
      if (!block) continue;
      const header = block.header || block;
      const tr = document.createElement('tr');
      tr.onclick = () => showDetail(h, block);
      tr.innerHTML = `
        <td>${header.height || h}</td>
        <td>${block.transactions ? block.transactions.length : (header.tx_count || 0)}</td>
        <td class="mono">${truncHash(header.state_root)}</td>
        <td>${formatTime(header.timestamp)}</td>
      `;
      tbody.appendChild(tr);
    } catch (e) {
      // Block may not exist yet
    }
  }
}

// ── Markets / DEX trade tape ────────────────────────
//
// Polls `seal_listTrades(selectedPair, since_id, 50)` every refresh
// tick (~2s, same cadence as the rest of the explorer). `since_id`
// keeps the request body small; we render newest-first capped at
// 100 rows. If the node doesn't expose the DEX RPCs (older builds
// or DEX-disabled config), the section silently shows "No pairs".

let knownPairs = new Set();
let selectedPair = null;
let tradeTapeBuffer = []; // newest last
let tradeTapeLastId = 0;
const TRADE_TAPE_MAX = 100;

async function refreshPairs() {
  let pairs = [];
  try {
    const r = await rpc('seal_listPairs');
    pairs = r.pairs || [];
  } catch (_) {
    // Older nodes may not expose seal_listPairs — leave the
    // dropdown empty rather than redlining the whole refresh tick.
    return;
  }
  const names = pairs.map(p => typeof p === 'string' ? p : (p.pair || `${p.base}/${p.quote}`));
  const next = new Set(names);
  // Cheap diff: rebuild only on add/remove.
  if (next.size === knownPairs.size && [...next].every(p => knownPairs.has(p))) {
    return;
  }
  knownPairs = next;
  const sel = document.getElementById('market-pair');
  // Honor whichever is set: a URL-deep-linked pair (`selectedPair`),
  // a previously-chosen pair from the dropdown, or none.
  const prev = selectedPair || sel.value;
  sel.innerHTML = '<option value="">Select a pair…</option>';
  for (const name of names) {
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name;
    if (name === prev) opt.selected = true;
    sel.appendChild(opt);
  }
  // If we deep-linked to a pair that the node now publishes, fire
  // the same setup the dropdown change handler does.
  if (selectedPair && next.has(selectedPair) && tradeTapeBuffer.length === 0) {
    pollTrades();
  }
  // If the previously-selected pair vanished, clear the tape.
  if (prev && !next.has(prev)) {
    selectedPair = null;
    tradeTapeBuffer = [];
    tradeTapeLastId = 0;
    renderTradeTape();
  }
}

function onPairChange(e) {
  const v = e.target.value || null;
  if (v === selectedPair) return;
  selectedPair = v;
  tradeTapeBuffer = [];
  tradeTapeLastId = 0;
  if (selectedPair) pollTrades();
  else renderTradeTape();
}

async function pollTrades() {
  if (!selectedPair) return;
  let r;
  try {
    r = await rpc('seal_listTrades', {
      pair: selectedPair,
      since_id: tradeTapeLastId,
      limit: 50,
    });
  } catch (e) {
    document.getElementById('market-summary').textContent = 'error: ' + e.message;
    return;
  }
  const newTrades = r.trades || [];
  if (newTrades.length) {
    tradeTapeBuffer = [...tradeTapeBuffer, ...newTrades].slice(-TRADE_TAPE_MAX);
    tradeTapeLastId = r.last_id || tradeTapeLastId;
  }
  document.getElementById('market-summary').textContent =
    `${tradeTapeBuffer.length} shown · last id ${tradeTapeLastId || '—'}`;
  renderTradeTape();
}

function renderTradeTape() {
  const tbody = document.getElementById('trade-list');
  tbody.innerHTML = '';
  if (!selectedPair) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = knownPairs.size === 0
      ? 'No DEX pairs published by this node.'
      : 'Pick a pair to start streaming trades.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  if (!tradeTapeBuffer.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'no trades yet on ' + selectedPair;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of [...tradeTapeBuffer].reverse()) {
    const tr = document.createElement('tr');
    const cells = [
      String(t.id ?? ''),
      t.side ?? '',
      String(t.price ?? ''),
      String(t.quantity ?? ''),
      truncAddr(t.maker),
      truncAddr(t.taker),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 1) td.className = (t.side === 'bid' ? 'side-bid' : 'side-ask');
      if (i === 4 || i === 5) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function truncAddr(addr) {
  if (!addr) return '—';
  const s = String(addr);
  if (s.length <= 18) return s;
  return s.slice(0, 10) + '…' + s.slice(-6);
}

// ── Tokens ──────────────────────────────────────────
//
// `seal_listTokens` returns one object per token, including
// `mint_authority` / `freeze_authority` / `fee_authority`
// (null when renounced — see
// `seal-node/src/rpc.rs::handle_list_tokens`). This panel
// re-renders only when the token set changes shape; common case
// is the table sits idle while the rest of the page ticks.

let lastTokensSig = '';

async function refreshTokens() {
  let tokens = [];
  try {
    const r = await rpc('seal_listTokens');
    tokens = r.tokens || [];
  } catch (_) {
    return; // older node without token RPCs — leave panel empty
  }
  const sig = JSON.stringify(tokens);
  if (sig === lastTokensSig) return;
  lastTokensSig = sig;
  renderTokenList(tokens);
}

function renderTokenList(tokens) {
  const tbody = document.getElementById('token-list');
  tbody.innerHTML = '';
  if (!tokens.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 8;
    td.className = 'dim';
    td.textContent = 'No tokens deployed.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of tokens) {
    const tr = document.createElement('tr');
    const cells = [
      t.symbol ?? '—',
      t.name ?? '—',
      String(t.total_supply ?? 0),
      String(t.transfer_fee_bps ?? 0),
      t.frozen ? 'YES' : 'no',
      authorityCell(t.mint_authority),
      authorityCell(t.freeze_authority),
      authorityCell(t.fee_authority),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 4 && t.frozen) td.style.color = 'var(--red)';
      if (i >= 5) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function authorityCell(value) {
  if (value === null || value === undefined) return 'renounced';
  return truncAddr(value);
}

// ── State-sync snapshots ────────────────────────────
//
// `seal_listSnapshots` returns the bounded roster of recent state
// snapshots captured at every epoch boundary. Default cap is 32, so
// the payload is tiny — no need for the sig-based skip-render that
// `refreshTokens` uses. Newest-first ordering matches what the RPC
// emits, which matches the late-joiner's heuristic of "take entry
// [0] to bootstrap from".
//
// If the node is on an older build that doesn't expose this RPC the
// panel silently shows "No snapshots retained yet" — the chain is
// still functional, just no late-joiner support.

let lastSnapshotsSig = '';

async function refreshSnapshots() {
  let snapshots = [];
  let total = 0;
  try {
    const r = await rpc('seal_listSnapshots', { limit: 32 });
    snapshots = r.snapshots || [];
    total = r.total_retained || snapshots.length;
  } catch (_) {
    return; // older node without snapshot RPCs — leave panel empty
  }
  const sig = JSON.stringify({ snapshots, total });
  if (sig === lastSnapshotsSig) return;
  lastSnapshotsSig = sig;
  document.getElementById('snapshot-count').textContent =
    snapshots.length === 0 ? '' : `(${snapshots.length} of ${total} retained)`;
  renderSnapshotList(snapshots);
}

function renderSnapshotList(snapshots) {
  const tbody = document.getElementById('snapshot-list');
  tbody.innerHTML = '';
  if (!snapshots.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'dim';
    td.textContent = 'No snapshots retained yet (need at least one epoch boundary to fire).';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const s of snapshots) {
    const tr = document.createElement('tr');
    const cells = [
      String(s.height ?? '—'),
      String(s.epoch ?? '—'),
      truncHash(s.state_root_hex),
      formatTime(s.captured_at_unix_secs),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 2) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

// ── Bridge ──────────────────────────────────────
//
// Aggregates `seal_getBridgeStatus` (per-token locked/minted +
// paused chains + invariant) with `seal_bridgeGetCommitteeKeyStatus`
// (committee-key fingerprint) into the Bridge section. Signature-
// gated so we only re-render on actual change; the section is a
// no-op on older nodes that don't expose either RPC.

let lastBridgeSig = '';

async function refreshBridge() {
  let status, keyStatus;
  try {
    [status, keyStatus] = await Promise.all([
      rpc('seal_getBridgeStatus'),
      rpc('seal_bridgeGetCommitteeKeyStatus'),
    ]);
  } catch (_) {
    return; // older node without these RPCs — leave the panel empty
  }
  // Fee RPC is independent — older nodes won't have it; we tolerate
  // a per-call failure and leave the field at 'unknown' rather than
  // skip the whole panel refresh.
  let feeStatus = null;
  try {
    feeStatus = await rpc('seal_getBridgeWithdrawalFee');
  } catch (_) {
    feeStatus = null;
  }
  const sig = JSON.stringify({ status, keyStatus, feeStatus });
  if (sig === lastBridgeSig) return;
  lastBridgeSig = sig;
  renderBridge(status, keyStatus, feeStatus);
}

function renderBridge(status, keyStatus, feeStatus) {
  const tbody = document.getElementById('bridge-per-token');
  tbody.innerHTML = '';
  const perToken = (status && status.per_token) || [];
  for (const row of perToken) {
    const tr = document.createElement('tr');
    const ok = (row.minted ?? 0) <= (row.locked ?? 0);
    const cells = [
      row.token ?? '—',
      String(row.locked ?? '—'),
      String(row.minted ?? '—'),
      ok ? '✓' : '⚠ minted > locked',
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 3 && !ok) td.style.color = '#f85149';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  if (!perToken.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'dim';
    td.textContent = 'No bridge activity yet.';
    tr.appendChild(td);
    tbody.appendChild(tr);
  }

  const keyEl = document.getElementById('bridge-committee-key-status');
  if (keyStatus && keyStatus.set) {
    const fp = keyStatus.fingerprint_sha2_hex || '';
    keyEl.textContent = 'sha2=' + (fp.length >= 16 ? fp.slice(0, 16) + '…' : fp);
    keyEl.title = fp;
    keyEl.style.color = '';
  } else {
    keyEl.textContent = 'unset';
    keyEl.style.color = '#f85149';
  }

  const pausedEl = document.getElementById('bridge-paused-chains');
  const pausedCount = (status && status.paused_chains && status.paused_chains.length) || 0;
  pausedEl.textContent = String(pausedCount);
  pausedEl.style.color = pausedCount > 0 ? '#f85149' : '';

  const invariantEl = document.getElementById('bridge-invariant');
  const invariantHolds = status && status.invariant_holds;
  invariantEl.textContent = invariantHolds ? 'holds' : 'VIOLATED';
  invariantEl.style.color = invariantHolds ? '' : '#f85149';

  // P8/§4.2 — bridge withdrawal fee. Renders as "<base_units>
  // (<SEAL>)" or "unknown" if the node didn't expose the RPC.
  const feeEl = document.getElementById('bridge-withdrawal-fee');
  if (feeStatus && typeof feeStatus.fee_base_units === 'number') {
    const base = feeStatus.fee_base_units;
    const seal = (typeof feeStatus.fee_seal === 'number')
      ? feeStatus.fee_seal
      : base / 1e9;
    if (base === 0) {
      feeEl.textContent = 'none';
      feeEl.style.color = '';
    } else {
      feeEl.textContent = `${base} (${seal.toFixed(9)} SEAL)`;
      feeEl.style.color = '';
    }
  } else {
    feeEl.textContent = 'unknown';
    feeEl.style.color = 'var(--dim, #888)';
  }

  const badge = document.getElementById('bridge-status-badge');
  if (!keyStatus || !keyStatus.set) {
    badge.textContent = '(committee key unset)';
    badge.style.color = '#f85149';
  } else if (pausedCount > 0) {
    badge.textContent = `(${pausedCount} chain paused)`;
    badge.style.color = '#f85149';
  } else if (!invariantHolds) {
    badge.textContent = '(invariant violated)';
    badge.style.color = '#f85149';
  } else {
    badge.textContent = '';
    badge.style.color = '';
  }
}

// ── Namespaces ──────────────────────────────────────

function renderNamespaces(namespaces) {
  const container = document.getElementById('namespace-list');
  if (namespaces.length === 0) {
    container.innerHTML = '<span style="color:var(--dim)">No namespaces deployed</span>';
    return;
  }
  container.innerHTML = namespaces
    .map(ns => `<span class="tag">${ns.name || ns}</span>`)
    .join('');
}

// ── Account lookup ──────────────────────────────────
//
// One-shot fetch — no auto-poll. Surfaces every per-owner view
// the node now exposes: SEAL balance, custom-token balances
// (`seal_listTokens` ∪ `seal_getTokenBalance`), open orders
// (`seal_listOrdersByOwner`), recent fills
// (`seal_listTradesByOwner`). Address is taken straight from the
// input box; the node validates the bech32m form server-side.
//
// The deep-link `?account=…` form pre-fills + auto-runs at
// connect time so a wallet can hand a user a "view me on the
// explorer" URL.

async function lookupAccount() {
  const addr = document.getElementById('account-input').value.trim();
  const errEl = document.getElementById('account-error');
  errEl.textContent = '';
  if (!addr) {
    errEl.textContent = 'Enter a seal1.../sealt1... address.';
    return;
  }
  try {
    // Twenty-two concurrent reads — node-side they hit independent
    // managers (balance / tokens / dex / bridge / governance /
    // private-tables / leases / namespaces / consensus / council),
    // so paralleling is safe and ~22× faster than serial.
    const [bal, tokensList, ordersResp, tradesResp, wrappedResp,
           govProposalsResp, govVotesResp, govLocksResp, frozenSymsResp,
           delsFromResp, delsToResp, createdResp,
           privTablesResp, leasesResp, namespacesResp,
           bridgeDepositsResp, bridgeWithdrawalsResp,
           validatorResp, councilResp, mintAuthResp,
           freezeAuthResp, feeAuthResp] = await Promise.all([
      rpc('seal_getBalance', { address: addr }),
      rpc('seal_listTokens', {}),
      rpc('seal_listOrdersByOwner', { address: addr }),
      rpc('seal_listTradesByOwner', { address: addr, limit: 100 }),
      rpc('seal_listBridgeWrappedBalances', { address: addr }),
      rpc('seal_govListProposalsByProposer', { address: addr }),
      rpc('seal_govListVotesByVoter', { address: addr }),
      rpc('seal_govListLocksByVoter', { address: addr }),
      rpc('seal_listFrozenSymbolsForAddress', { address: addr }),
      rpc('seal_govListDelegationsFrom', { address: addr }),
      rpc('seal_govListDelegationsTo', { address: addr }),
      rpc('seal_listTokensByCreator', { address: addr }),
      rpc('seal_listPrivateTablesByOwner', { address: addr }),
      rpc('seal_listLeasesByOwner', { address: addr }),
      rpc('seal_listNamespacesByOwner', { address: addr }),
      rpc('seal_listBridgeDepositsByRecipient', { address: addr }),
      rpc('seal_listBridgeWithdrawalsByInitiator', { address: addr }),
      rpc('seal_getValidatorByAddress', { address: addr }),
      rpc('seal_getCouncilMemberByAddress', { address: addr }),
      rpc('seal_listTokensByMintAuthority', { address: addr }),
      rpc('seal_listTokensByFreezeAuthority', { address: addr }),
      rpc('seal_listTokensByFeeAuthority', { address: addr }),
    ]);
    document.getElementById('account-result').style.display = 'block';
    document.getElementById('account-seal').textContent =
      String(bal.balance ?? 0);

    // Per-token balances. Fetch in parallel; skip zero-balance
    // rows so a deployed-but-unheld token doesn't pad the table.
    const tokens = tokensList.tokens || [];
    const tokenBalances = await Promise.all(tokens.map(async (t) => {
      try {
        const r = await rpc('seal_getTokenBalance',
          { symbol: t.symbol, address: addr });
        return { ...t, balance: r.balance ?? 0 };
      } catch (_) {
        return { ...t, balance: 0 };
      }
    }));
    const heldTokens = tokenBalances.filter(t => t.balance > 0);
    document.getElementById('account-tokens-count').textContent =
      String(heldTokens.length);
    renderAccountTokens(heldTokens);

    const orders = ordersResp.orders || [];
    document.getElementById('account-orders-count').textContent =
      String(orders.length);
    renderAccountOrders(orders);

    const trades = tradesResp.trades || [];
    document.getElementById('account-trades-count').textContent =
      String(trades.length);
    renderAccountTrades(trades, addr);

    const wrapped = wrappedResp.balances || [];
    document.getElementById('account-wrapped-count').textContent =
      String(wrapped.length);
    renderAccountWrapped(wrapped);

    const govProposals = govProposalsResp.proposals || [];
    document.getElementById('account-proposals-count').textContent =
      String(govProposals.length);
    renderAccountProposals(govProposals);

    const govVotes = govVotesResp.votes || [];
    document.getElementById('account-votes-count').textContent =
      String(govVotes.length);
    renderAccountGovVotes(govVotes);

    const govLocks = govLocksResp.locks || [];
    document.getElementById('account-locks-count').textContent =
      String(govLocks.length);
    renderAccountLocks(govLocks);

    const frozenSyms = frozenSymsResp.symbols || [];
    document.getElementById('account-frozen-count').textContent =
      String(frozenSyms.length);
    renderAccountFrozen(frozenSyms);

    const delsFrom = delsFromResp.delegations || [];
    const delsTo = delsToResp.delegations || [];
    document.getElementById('account-delegations-count').textContent =
      `${delsFrom.length} / ${delsTo.length}`;
    renderAccountDelegations('account-delegations-out-body', delsFrom, 'delegate');
    renderAccountDelegations('account-delegations-in-body', delsTo, 'delegator');

    const created = createdResp.tokens || [];
    document.getElementById('account-created-count').textContent =
      String(created.length);
    renderAccountCreated(created);

    const privTables = privTablesResp.tables || [];
    document.getElementById('account-priv-tables-count').textContent =
      String(privTables.length);
    renderAccountPrivTables(privTables);

    const leases = leasesResp.leases || [];
    document.getElementById('account-leases-count').textContent =
      String(leases.length);
    renderAccountLeases(leases);

    const namespaces = namespacesResp.namespaces || [];
    document.getElementById('account-namespaces-count').textContent =
      String(namespaces.length);
    renderAccountNamespaces(namespaces);

    const bridgeDeposits = bridgeDepositsResp.deposits || [];
    document.getElementById('account-bridge-deposits-count').textContent =
      String(bridgeDeposits.length);
    renderAccountBridgeDeposits(bridgeDeposits);

    const bridgeWithdrawals = bridgeWithdrawalsResp.withdrawals || [];
    document.getElementById('account-bridge-withdrawals-count').textContent =
      String(bridgeWithdrawals.length);
    renderAccountBridgeWithdrawals(bridgeWithdrawals);

    renderAccountValidator(validatorResp ? validatorResp.validator : null);
    renderAccountCouncil(councilResp ? councilResp.member : null);

    const mintAuthTokens = (mintAuthResp && mintAuthResp.tokens) || [];
    document.getElementById('account-mint-auth-count').textContent =
      String(mintAuthTokens.length);
    renderAccountMintAuthorityTokens(mintAuthTokens, addr);

    const freezeAuthTokens = (freezeAuthResp && freezeAuthResp.tokens) || [];
    document.getElementById('account-freeze-auth-count').textContent =
      String(freezeAuthTokens.length);
    renderAccountFreezeAuthorityTokens(freezeAuthTokens, addr);

    const feeAuthTokens = (feeAuthResp && feeAuthResp.tokens) || [];
    document.getElementById('account-fee-auth-count').textContent =
      String(feeAuthTokens.length);
    renderAccountFeeAuthorityTokens(feeAuthTokens, addr);
  } catch (e) {
    errEl.textContent = `Lookup failed: ${e.message}`;
    document.getElementById('account-result').style.display = 'none';
  }
}

function clearAccount() {
  document.getElementById('account-input').value = '';
  document.getElementById('account-result').style.display = 'none';
  document.getElementById('account-error').textContent = '';
}

function renderAccountTokens(tokens) {
  const tbody = document.getElementById('account-tokens-body');
  tbody.innerHTML = '';
  if (!tokens.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'dim';
    td.textContent = 'No custom tokens held.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of tokens) {
    const tr = document.createElement('tr');
    const cells = [
      t.symbol ?? '?',
      String(t.balance),
      String(t.decimals ?? 0),
      t.frozen ? 'YES' : 'no',
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 3 && t.frozen) td.style.color = 'var(--red, #c33)';
      if (i === 1) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountOrders(orders) {
  const tbody = document.getElementById('account-orders-body');
  tbody.innerHTML = '';
  if (!orders.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'No open orders.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const o of orders) {
    const tr = document.createElement('tr');
    const cells = [
      o.pair ?? '?',
      String(o.id ?? '?'),
      o.side ?? '?',
      String(o.price ?? 0),
      String(o.quantity ?? 0),
      String(o.remaining ?? 0),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i >= 3) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountProposals(proposals) {
  const tbody = document.getElementById('account-proposals-body');
  tbody.innerHTML = '';
  if (!proposals.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'dim';
    td.textContent = 'No proposals authored.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const p of proposals) {
    const tr = document.createElement('tr');
    const cells = [
      String(p.id ?? '?'),
      p.track ?? '?',
      p.status ?? '?',
      p.title ?? '?',
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountGovVotes(votes) {
  const tbody = document.getElementById('account-govvotes-body');
  tbody.innerHTML = '';
  if (!votes.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'No governance votes cast.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const v of votes) {
    const tr = document.createElement('tr');
    const cells = [
      String(v.proposal_id ?? '?'),
      v.choice ?? '?',
      String(v.stake ?? 0),
      v.conviction ?? '?',
      String(v.weight ?? 0),
      String(v.unlock_epoch ?? 0),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0 || i >= 2) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountLocks(locks) {
  const tbody = document.getElementById('account-locks-body');
  tbody.innerHTML = '';
  if (!locks.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.className = 'dim';
    td.textContent = 'No active conviction locks.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const l of locks) {
    const tr = document.createElement('tr');
    const cells = [
      String(l.proposal_id ?? '?'),
      String(l.amount ?? 0),
      String(l.unlock_epoch ?? 0),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountDelegations(tbodyId, delegations, peerField) {
  const tbody = document.getElementById(tbodyId);
  tbody.innerHTML = '';
  if (!delegations.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.className = 'dim';
    td.textContent = peerField === 'delegate'
      ? 'No outgoing delegations.'
      : 'No incoming delegations.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const d of delegations) {
    const tr = document.createElement('tr');
    const cells = [
      d.track ?? '?',
      d[peerField] ?? '?',
      String(d.weight ?? 0),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i >= 1) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountBridgeDeposits(deposits) {
  const tbody = document.getElementById('account-bridge-deposits-body');
  tbody.innerHTML = '';
  if (!deposits.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'No bridge deposits.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const d of deposits) {
    const tr = document.createElement('tr');
    const processed = d.processed === true;
    const cells = [
      d.id ?? '?',
      d.source_chain ?? '?',
      d.token ?? '?',
      String(d.amount ?? 0),
      String(d.confirmations ?? 0),
      processed ? 'yes' : 'no',
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 3 || i === 4) td.className = 'mono';
      // Unprocessed deposits are still in flight — dim them so
      // the eye lands on processed (i.e. minted) ones first.
      if (i === 5 && !processed) td.style.color = 'var(--dim, #888)';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountBridgeWithdrawals(withdrawals) {
  const tbody = document.getElementById('account-bridge-withdrawals-body');
  tbody.innerHTML = '';
  if (!withdrawals.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'No bridge withdrawals.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const w of withdrawals) {
    const tr = document.createElement('tr');
    const executed = w.executed === true;
    // Dest addresses on Solana/Stellar are 32-56 chars — too wide
    // for a comfortable column, so render the head + tail with an
    // ellipsis. Full string still in the JSON for callers.
    const dest = w.dest_address || '';
    const destShort = dest.length > 16
      ? dest.slice(0, 8) + '…' + dest.slice(-6)
      : dest;
    const cells = [
      w.id ?? '?',
      w.dest_chain ?? '?',
      w.token ?? '?',
      String(w.amount ?? 0),
      destShort,
      executed ? 'yes' : 'pending',
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 3) td.className = 'mono';
      if (i === 4) {
        td.className = 'mono';
        td.title = dest;
      }
      // Pending withdrawals have not yet been executed on the
      // destination chain — dim so the eye lands on completed
      // ones first.
      if (i === 5 && !executed) td.style.color = 'var(--dim, #888)';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountValidator(validator) {
  const statusEl = document.getElementById('account-validator-status');
  const detailEl = document.getElementById('account-validator-detail');
  if (!validator) {
    statusEl.textContent = 'no';
    statusEl.style.color = 'var(--dim, #888)';
    detailEl.textContent = '';
    return;
  }
  const active = validator.active === true;
  statusEl.textContent = active ? 'ACTIVE' : 'inactive';
  // Inactive (slashed/unbonding) validators are visually distinct
  // from non-validators — both unhelpful but for different reasons.
  statusEl.style.color = active ? 'var(--green, #2a7)' : 'var(--red, #c33)';
  const stake = validator.stake ?? 0;
  // ML-DSA pubkeys are long; show the first 16 hex chars (a near-
  // unique fingerprint at 64 bits) — full hex is in the JSON for
  // callers that need to verify identity exactly.
  const pk = (validator.public_key_hex || '').slice(0, 16);
  detailEl.textContent =
    `stake: ${stake} micro-SEAL · pubkey: ${pk}…`;
}

function renderAccountMintAuthorityTokens(tokens, addr) {
  const tbody = document.getElementById('account-mint-auth-body');
  tbody.innerHTML = '';
  if (!tokens.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.className = 'dim';
    td.textContent = 'No mint authority on any token.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of tokens) {
    const tr = document.createElement('tr');
    const creator = t.creator || '';
    // "self" when this address is the original creator AND still
    // the mint authority (the common pre-rotation case); else
    // head…tail of the bech32m creator address. The asymmetry
    // between this column and "Tokens created by this address"
    // is the whole point of the table — they reveal which tokens
    // moved authority and which didn't.
    let creatorDisp;
    if (creator === addr) {
      creatorDisp = 'self';
    } else if (creator.length > 16) {
      creatorDisp = creator.slice(0, 8) + '…' + creator.slice(-6);
    } else {
      creatorDisp = creator;
    }
    const cells = [
      t.symbol ?? '?',
      t.name ?? '?',
      String(t.decimals ?? 0),
      String(t.total_supply ?? 0),
      creatorDisp,
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 3) td.className = 'mono';
      if (i === 4) {
        td.className = 'mono';
        td.title = creator;
        // Dim "self" so the eye lands on rotated-into-this-address
        // rows — those are the surprising / interesting ones.
        if (creator === addr) td.style.color = 'var(--dim, #888)';
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountFreezeAuthorityTokens(tokens, addr) {
  const tbody = document.getElementById('account-freeze-auth-body');
  tbody.innerHTML = '';
  if (!tokens.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'No freeze authority on any token.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of tokens) {
    const tr = document.createElement('tr');
    const creator = t.creator || '';
    let creatorDisp;
    if (creator === addr) {
      creatorDisp = 'self';
    } else if (creator.length > 16) {
      creatorDisp = creator.slice(0, 8) + '…' + creator.slice(-6);
    } else {
      creatorDisp = creator;
    }
    const globallyFrozen = t.frozen === true;
    const cells = [
      t.symbol ?? '?',
      t.name ?? '?',
      String(t.decimals ?? 0),
      String(t.total_supply ?? 0),
      globallyFrozen ? 'YES' : 'no',
      creatorDisp,
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 3) td.className = 'mono';
      // Globally-frozen tokens are the operationally-actionable
      // ones — color-shift to red so the eye lands on tokens
      // currently in kill-switch state.
      if (i === 4 && globallyFrozen) td.style.color = 'var(--red, #c33)';
      if (i === 5) {
        td.className = 'mono';
        td.title = creator;
        if (creator === addr) td.style.color = 'var(--dim, #888)';
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountFeeAuthorityTokens(tokens, addr) {
  const tbody = document.getElementById('account-fee-auth-body');
  tbody.innerHTML = '';
  if (!tokens.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'No fee authority on any token.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of tokens) {
    const tr = document.createElement('tr');
    const creator = t.creator || '';
    let creatorDisp;
    if (creator === addr) {
      creatorDisp = 'self';
    } else if (creator.length > 16) {
      creatorDisp = creator.slice(0, 8) + '…' + creator.slice(-6);
    } else {
      creatorDisp = creator;
    }
    const feeBps = Number(t.transfer_fee_bps ?? 0);
    const feePct = (feeBps / 100).toFixed(2);
    const cells = [
      t.symbol ?? '?',
      t.name ?? '?',
      String(t.decimals ?? 0),
      String(t.total_supply ?? 0),
      `${feeBps} (${feePct}%)`,
      creatorDisp,
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 3) td.className = 'mono';
      // Non-zero fee is the operationally-interesting state — a
      // fee-authority operator deciding whether to rotate or
      // renounce wants to see the live rate at a glance.
      if (i === 4) {
        td.className = 'mono';
        if (feeBps > 0) td.style.color = 'var(--accent, #b46a00)';
        else td.style.color = 'var(--dim, #888)';
      }
      if (i === 5) {
        td.className = 'mono';
        td.title = creator;
        if (creator === addr) td.style.color = 'var(--dim, #888)';
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountCouncil(member) {
  const statusEl = document.getElementById('account-council-status');
  const detailEl = document.getElementById('account-council-detail');
  if (!member) {
    statusEl.textContent = 'no';
    statusEl.style.color = 'var(--dim, #888)';
    detailEl.textContent = '';
    return;
  }
  statusEl.textContent = 'SEATED';
  statusEl.style.color = 'var(--green, #2a7)';
  const name = member.name || '(unnamed)';
  const ts = member.term_start_epoch ?? 0;
  const te = member.term_end_epoch ?? 0;
  detailEl.textContent =
    `Tech Council: ${name} · term epochs ${ts}–${te}`;
}

function renderAccountNamespaces(namespaces) {
  const tbody = document.getElementById('account-namespaces-body');
  tbody.innerHTML = '';
  if (!namespaces.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.className = 'dim';
    td.textContent = 'No namespaces deployed.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const n of namespaces) {
    const tr = document.createElement('tr');
    // schema_hash is rendered short — just first 12 chars for
    // table fit. Full hash is in the JSON if a caller needs it.
    const schemaShort = (n.schema_hash || '').slice(0, 12);
    const cells = [
      n.name ?? '?',
      n.visibility ?? '?',
      String(n.replication ?? 0),
      schemaShort + (n.schema_hash && n.schema_hash.length > 12 ? '…' : ''),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 2 || i === 3) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountLeases(leases) {
  const tbody = document.getElementById('account-leases-body');
  tbody.innerHTML = '';
  if (!leases.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.className = 'dim';
    td.textContent = 'No storage leases owned.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const l of leases) {
    const tr = document.createElement('tr');
    const expired = l.expired === true;
    const cells = [
      l.table ?? '?',
      String(l.row_count ?? 0),
      String(l.byte_size ?? 0),
      String(l.paid_through_us ?? 0),
      expired ? 'YES' : 'no',
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i >= 1 && i <= 3) td.className = 'mono';
      if (i === 4 && expired) td.style.color = 'var(--red, #c33)';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountPrivTables(tables) {
  const tbody = document.getElementById('account-priv-tables-body');
  tbody.innerHTML = '';
  if (!tables.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.className = 'dim';
    td.textContent = 'No private tables owned.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of tables) {
    const tr = document.createElement('tr');
    const cells = [
      t.name ?? '?',
      t.type ?? '?',
      String(t.row_count ?? 0),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 2) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountCreated(tokens) {
  const tbody = document.getElementById('account-created-body');
  tbody.innerHTML = '';
  if (!tokens.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 5;
    td.className = 'dim';
    td.textContent = 'No tokens created by this address.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of tokens) {
    const tr = document.createElement('tr');
    // mint_authority is null after a renounce — render as
    // "renounced" rather than "null" so the operational meaning
    // is obvious.
    const mintAuth = t.mint_authority == null
      ? 'renounced'
      : (t.mint_authority || '?');
    const cells = [
      t.symbol ?? '?',
      t.name ?? '?',
      String(t.decimals ?? 0),
      String(t.total_supply ?? 0),
      mintAuth,
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 3 || i === 4) td.className = 'mono';
      if (i === 4 && mintAuth === 'renounced') td.style.color = 'var(--dim, #888)';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountFrozen(symbols) {
  const host = document.getElementById('account-frozen-list');
  host.innerHTML = '';
  if (!symbols.length) {
    host.textContent = 'Not frozen on any token.';
    return;
  }
  // Render each symbol as a small tag, red since it indicates a
  // restriction. Same pattern as the existing namespace tag list
  // but with the alert color.
  for (const sym of symbols) {
    const span = document.createElement('span');
    span.className = 'tag';
    span.style.color = 'var(--red, #c33)';
    span.style.borderColor = 'var(--red, #c33)';
    span.textContent = sym;
    host.appendChild(span);
  }
}

function renderAccountWrapped(wrapped) {
  const tbody = document.getElementById('account-wrapped-body');
  tbody.innerHTML = '';
  if (!wrapped.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 3;
    td.className = 'dim';
    td.textContent = 'No wrapped balances. Bridge a deposit to see wSOL/wXLM/wUSDC entries here.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const b of wrapped) {
    const tr = document.createElement('tr');
    const cells = [
      b.token ?? '?',
      b.chain ?? '?',
      String(b.balance ?? 0),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i === 0) td.style.fontWeight = '600';
      if (i === 2) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

function renderAccountTrades(trades, viewerAddr) {
  const tbody = document.getElementById('account-trades-body');
  tbody.innerHTML = '';
  if (!trades.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'dim';
    td.textContent = 'No retained trades — pair history is bounded at 10 000 entries per pair.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  for (const t of trades) {
    const tr = document.createElement('tr');
    const role = t.maker === viewerAddr ? 'maker' : 'taker';
    const cells = [
      t.pair ?? '?',
      String(t.id ?? '?'),
      role,
      String(t.price ?? 0),
      String(t.quantity ?? 0),
      formatTime(t.timestamp),
    ];
    for (let i = 0; i < cells.length; i++) {
      const td = document.createElement('td');
      td.textContent = cells[i];
      if (i >= 3) td.className = 'mono';
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
}

// ── Block detail ────────────────────────────────────

function showDetail(height, block) {
  document.getElementById('detail-height').textContent = height;
  document.getElementById('detail-json').textContent = JSON.stringify(block, null, 2);
  document.getElementById('block-detail').style.display = 'block';
}

function hideDetail() {
  document.getElementById('block-detail').style.display = 'none';
}

// ── Formatting ──────────────────────────────────────

function truncHash(hash) {
  if (!hash) return '-';
  const s = String(hash);
  if (s.length <= 16) return s;
  return s.slice(0, 10) + '...' + s.slice(-6);
}

function formatUptime(secs) {
  if (!secs) return '-';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatTime(ts) {
  if (!ts) return '-';
  // ts may be seconds or milliseconds
  const ms = ts > 1e12 ? ts : ts * 1000;
  return new Date(ms).toLocaleTimeString();
}

// ── Auto-connect on load ────────────────────────────

window.addEventListener('load', () => {
  const params = new URLSearchParams(window.location.search);
  if (params.has('rpc')) {
    document.getElementById('rpc-url').value = params.get('rpc');
  }
  if (params.has('pair')) {
    // Pre-select a pair from URL so deep-links to a market are
    // shareable. The dropdown won't have the option populated yet
    // (that needs an RPC roundtrip), so stash the desired value and
    // let `refreshPairs` honor it on first tick.
    selectedPair = params.get('pair');
  }
  if (params.has('account')) {
    // Deep-link form: a wallet can hand the user a "view me on the
    // explorer" URL. We populate the input and fire the lookup once
    // `connect()` resolves the RPC URL so the page renders without
    // a double-click.
    document.getElementById('account-input').value = params.get('account');
  }
  document.getElementById('market-pair').addEventListener('change', onPairChange);
  // Pressing Enter in the account input runs the lookup — saves a
  // mouse trip when pasting an address.
  document.getElementById('account-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') lookupAccount();
  });
  connect().then(() => {
    if (params.has('account')) lookupAccount();
  });
});
