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
  connect();
});
