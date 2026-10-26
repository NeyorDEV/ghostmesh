const invoke = window.__TAURI__ ? window.__TAURI__.core.invoke : async () => {};

// DOM Elements
const elStatusLabel = document.getElementById('status-label');
const elStatusBadge = document.getElementById('status-indicator');
const elVip = document.getElementById('val-vip');
const elEndpoint = document.getElementById('val-endpoint');
const elNodeId = document.getElementById('val-nodeid');
const elPeersCount = document.getElementById('peers-count');
const elPeersTbody = document.getElementById('peers-tbody');

// Modals
const modalInvite = document.getElementById('modal-invite');
const modalJoin = document.getElementById('modal-join');
const elTicketText = document.getElementById('ticket-text');
const elInputTicket = document.getElementById('input-join-ticket');

// Buttons
const btnInvite = document.getElementById('btn-invite');
const btnJoin = document.getElementById('btn-join');
const btnCopyTicket = document.getElementById('btn-copy-ticket');
const btnSubmitJoin = document.getElementById('btn-submit-join');
const btnRefresh = document.getElementById('btn-refresh');

async function updateStatus() {
  try {
    const status = await invoke('get_node_status');
    if (status) {
      elStatusLabel.textContent = status.is_active ? 'Active • Mesh Ready' : 'Standby';
      elNodeId.textContent = status.node_id;
      elEndpoint.textContent = status.public_endpoint;
      if (status.virtual_ip) {
        elVip.textContent = status.virtual_ip;
      }
      elPeersCount.textContent = status.peers_count;
    }
  } catch (err) {
    // When running inside browser dev server without Tauri backend
    elStatusLabel.textContent = 'GUI Mode (Connecting...)';
    elNodeId.textContent = 'Simulated Local Node';
    elEndpoint.textContent = '0.0.0.0:4242';
  }
}

async function updatePeers() {
  try {
    const peers = await invoke('get_peers');
    if (!peers || peers.length === 0) {
      elPeersTbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="4">No peers connected yet. Click "Invite Peer" or "Join Network" to establish a direct P2P link.</td>
        </tr>`;
      return;
    }

    elPeersTbody.innerHTML = peers.map(p => `
      <tr>
        <td class="font-mono text-truncate" style="max-width: 180px;">${p.node_id}</td>
        <td class="font-mono">${p.endpoint}</td>
        <td><span class="green-text">● ${p.state}</span></td>
        <td>${p.last_seen_secs}s ago</td>
      </tr>
    `).join('');
  } catch (err) {
    // Silently continue
  }
}

// Modal handling
btnInvite.addEventListener('click', async () => {
  modalInvite.classList.add('active');
  elTicketText.textContent = 'Generating encrypted ticket...';
  try {
    const ticket = await invoke('create_invite');
    elTicketText.textContent = ticket || 'gm1_simulated_ticket_for_testing';
  } catch (e) {
    elTicketText.textContent = 'Failed to generate ticket: ' + e;
  }
});

btnJoin.addEventListener('click', () => {
  elInputTicket.value = '';
  modalJoin.classList.add('active');
});

document.querySelectorAll('[data-close]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.getAttribute('data-close');
    document.getElementById(target).classList.remove('active');
  });
});

btnCopyTicket.addEventListener('click', () => {
  navigator.clipboard.writeText(elTicketText.textContent);
  btnCopyTicket.textContent = 'Copied!';
  setTimeout(() => {
    btnCopyTicket.textContent = 'Copy Ticket';
  }, 2000);
});

btnSubmitJoin.addEventListener('click', async () => {
  const ticket = elInputTicket.value.trim();
  if (!ticket) return;

  btnSubmitJoin.disabled = true;
  btnSubmitJoin.textContent = 'Connecting...';
  try {
    await invoke('join_peer', { ticket });
    modalJoin.classList.remove('active');
    setTimeout(updatePeers, 500);
  } catch (e) {
    alert('Join error: ' + e);
  } finally {
    btnSubmitJoin.disabled = false;
    btnSubmitJoin.textContent = 'Connect';
  }
});

btnRefresh.addEventListener('click', () => {
  updateStatus();
  updatePeers();
});

// Periodic polling
updateStatus();
updatePeers();
setInterval(updateStatus, 3000);
setInterval(updatePeers, 2000);
