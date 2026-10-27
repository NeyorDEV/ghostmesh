function invoke(cmd, args) {
  if (window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke) {
    return window.__TAURI__.core.invoke(cmd, args);
  }
  return Promise.resolve(null);
}

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

// GhostDrop DOM Elements
const selectTargetPeer = document.getElementById('gd-target-peer');
const inputFilePath = document.getElementById('gd-filepath-input');
const inputFileElem = document.getElementById('gd-file-elem');
const btnBrowseFile = document.getElementById('btn-browse-file');
const btnStartTransfer = document.getElementById('btn-start-transfer');
const btnOpenTransfers = document.getElementById('btn-open-transfers');

// Transfer Monitor
const transferMonitor = document.getElementById('transfer-monitor');
const tmFilename = document.getElementById('tm-filename');
const tmSpeed = document.getElementById('tm-speed');
const tmFill = document.getElementById('tm-fill');
const tmStatus = document.getElementById('tm-status');
const tmStats = document.getElementById('tm-stats');

let cachedPeers = [];
let activeExitNode = null;

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
    elStatusLabel.textContent = 'Standby (Connecting...)';
    elNodeId.textContent = 'Simulated Local Node';
    elEndpoint.textContent = '0.0.0.0:4242';
  }
}

function formatLastSeen(secs) {
  if (secs < 5) return 'just now';
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

async function disconnectPeer(nodeId) {
  if (!confirm(`Are you sure you want to disconnect peer ${nodeId.substring(0, 10)}...?`)) {
    return;
  }
  try {
    await invoke('disconnect_peer', { nodeId });
    await updatePeers();
    await updateStatus();
  } catch (err) {
    alert('Failed to disconnect: ' + err);
  }
}

async function updatePeers() {
  try {
    const peers = await invoke('get_peers');
    cachedPeers = peers || [];

    if (!peers || peers.length === 0) {
      elPeersTbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="5">No peers connected yet. Click "Invite Peer" or "Join Network" to establish a direct P2P link.</td>
        </tr>`;
      syncPeerSelect([]);
      return;
    }

    elPeersTbody.innerHTML = peers.map(p => `
      <tr>
        <td class="font-mono text-truncate" style="max-width: 180px;">${p.node_id}</td>
        <td class="font-mono">${p.endpoint}</td>
        <td><span class="${p.state === 'Connected' ? 'green-text' : 'text-muted'}">${p.state}</span></td>
        <td>${formatLastSeen(p.last_seen_secs)}</td>
        <td>
          <button class="btn-rdp" onclick="launchRdp('${p.node_id}')" title="Windows Remote Desktop">RDP</button>
          <button class="btn-chat" onclick="openChat('${p.node_id}')" title="Encrypted Chat">Chat</button>
          <button class="btn-clip" onclick="sendClipboardTo('${p.node_id}')" title="Send Clipboard to Peer">Clip</button>
          <button class="btn-exit ${activeExitNode === p.node_id ? 'active' : ''}" onclick="toggleExitNode('${p.node_id}')" title="Route all Internet through this peer">${activeExitNode === p.node_id ? 'Exit: ON' : 'Exit Node'}</button>
          <button class="btn-disconnect" onclick="disconnectPeer('${p.node_id}')" title="Disconnect and remove peer">Disconnect</button>
        </td>
      </tr>
    `).join('');

    syncPeerSelect(peers);
  } catch (err) {
    // Silently continue
  }
}

function syncPeerSelect(peers) {
  const currentVal = selectTargetPeer.value;
  let options = '<option value="">Select a connected peer...</option>';
  peers.forEach(p => {
    options += `<option value="${p.endpoint}">${p.endpoint} (Node: ${p.node_id.substring(0, 10)}...)</option>`;
  });
  selectTargetPeer.innerHTML = options;
  if (currentVal && peers.some(p => p.endpoint === currentVal)) {
    selectTargetPeer.value = currentVal;
  }
  checkTransferReady();
}

function checkTransferReady() {
  const hasPeer = selectTargetPeer.value.trim().length > 0;
  const hasFile = inputFilePath.value.trim().length > 0;
  btnStartTransfer.disabled = !(hasPeer && hasFile);
}

selectTargetPeer.addEventListener('change', checkTransferReady);
inputFilePath.addEventListener('input', checkTransferReady);

// File Browse Handling
btnBrowseFile.addEventListener('click', () => {
  inputFileElem.click();
});

inputFileElem.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) {
    // In Tauri webview or desktop, file.name or full path
    inputFilePath.value = file.name;
    checkTransferReady();
  }
});

// Drag and drop support
const dropZone = document.querySelector('.ghostdrop-card');
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.style.borderColor = 'var(--accent)';
});

dropZone.addEventListener('dragleave', () => {
  dropZone.style.borderColor = 'var(--border)';
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.style.borderColor = 'var(--border)';
  if (e.dataTransfer.files.length > 0) {
    const file = e.dataTransfer.files[0];
    inputFilePath.value = file.name;
    checkTransferReady();
  }
});

// Start Transfer
btnStartTransfer.addEventListener('click', async () => {
  const target = selectTargetPeer.value;
  const filePath = inputFilePath.value.trim();
  if (!target || !filePath) return;

  btnStartTransfer.disabled = true;
  btnStartTransfer.textContent = 'Initiating...';

  try {
    await invoke('ghostdrop_send', { target, filePath });
    transferMonitor.style.display = 'block';
  } catch (e) {
    alert('GhostDrop error: ' + e);
  } finally {
    btnStartTransfer.textContent = 'Send with GhostDrop';
    checkTransferReady();
  }
});

// Open Transfers Folder
btnOpenTransfers.addEventListener('click', async () => {
  try {
    await invoke('ghostdrop_open_folder');
  } catch (e) {
    alert('Cannot open folder: ' + e);
  }
});

// Monitor GhostDrop Transfer State
async function updateTransferMonitor() {
  try {
    const st = await invoke('ghostdrop_get_status');
    if (!st) {
      return;
    }

    if (st.is_active || st.is_completed) {
      transferMonitor.style.display = 'block';
      tmFilename.textContent = (st.direction === 'sending' ? 'Sending: ' : 'Receiving: ') + st.filename;
      tmSpeed.textContent = st.speed_mbps > 0 ? `${st.speed_mbps.toFixed(1)} MB/s` : '-- MB/s';
      tmFill.style.width = `${Math.min(100, Math.max(0, st.percent))}%`;
      tmStatus.textContent = st.status_message;

      const currentMB = (st.transferred_bytes / 1000000).toFixed(1);
      const totalMB = (st.total_bytes / 1000000).toFixed(1);
      tmStats.textContent = `${currentMB} MB / ${totalMB} MB (${st.percent.toFixed(0)}%)`;
    }
  } catch (e) {
    // Silently continue
  }
}

// QR & GhostSync DOM Elements
const qrWrapper = document.getElementById('qr-wrapper');
const ticketQr = document.getElementById('ticket-qr');
const btnToggleQr = document.getElementById('btn-toggle-qr');
const syncDirInput = document.getElementById('sync-dir-input');
const btnSaveSyncDir = document.getElementById('btn-save-sync-dir');
const syncStatusMsg = document.getElementById('sync-status-msg');
const syncBadgeLabel = document.getElementById('sync-badge-label');
const syncStatusBadge = document.getElementById('sync-status-badge');

// Modal handling
btnInvite.addEventListener('click', async () => {
  modalInvite.classList.add('active');
  elTicketText.textContent = 'Generating encrypted ticket...';
  ticketQr.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">Generating QR Code...</div>';
  try {
    const ticket = await invoke('create_invite');
    elTicketText.textContent = ticket || 'gm1_simulated_ticket_for_testing';

    if (ticket) {
      try {
        const qrSvg = await invoke('generate_ticket_qr', { ticket });
        if (qrSvg) {
          ticketQr.innerHTML = qrSvg;
        }
      } catch (err) {
        ticketQr.innerHTML = '<div style="color:var(--text-muted);font-size:12px;">QR Code unavailable</div>';
      }
    }
  } catch (e) {
    elTicketText.textContent = 'Failed to generate ticket: ' + e;
  }
});

btnToggleQr.addEventListener('click', () => {
  if (qrWrapper.style.display === 'none') {
    qrWrapper.style.display = 'flex';
  } else {
    qrWrapper.style.display = 'none';
  }
});

// GhostSync Handling
btnSaveSyncDir.addEventListener('click', async () => {
  const dir = syncDirInput.value.trim();
  if (!dir) return;

  btnSaveSyncDir.disabled = true;
  btnSaveSyncDir.textContent = 'Saving...';
  try {
    await invoke('ghostsync_set_dir', { dir });
    updateSyncStatus();
  } catch (e) {
    alert('GhostSync error: ' + e);
  } finally {
    btnSaveSyncDir.disabled = false;
    btnSaveSyncDir.textContent = 'Set Folder';
  }
});

async function updateSyncStatus() {
  try {
    const st = await invoke('ghostsync_get_status');
    if (st) {
      syncStatusMsg.textContent = st.status_message;
      if (st.is_active && st.watched_dir) {
        syncBadgeLabel.textContent = 'Active Sync';
        syncStatusBadge.style.color = '#10b981';
      } else {
        syncBadgeLabel.textContent = 'Idle';
        syncStatusBadge.style.color = 'var(--text-muted)';
      }
    }
  } catch (e) {
    // Silently continue
  }
}

btnJoin.addEventListener('click', () => {
  elInputTicket.value = '';
  modalJoin.classList.add('active');
});

document.querySelectorAll('[data-close]').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.getAttribute('data-close');
    const el = document.getElementById(target);
    if (el) {
      el.classList.remove('active');
      el.style.display = 'none';
    }
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

// Incoming Request Alert DOM Elements
const incomingAlert = document.getElementById('incoming-alert');
const alertRequesterId = document.getElementById('alert-requester-id');
const btnAcceptRequest = document.getElementById('btn-accept-request');
const btnDeclineRequest = document.getElementById('btn-decline-request');
const knownTbody = document.getElementById('known-tbody');
const knownCount = document.getElementById('known-count');

let activePendingRequest = null;

async function updateIncomingRequests() {
  try {
    const req = await invoke('get_pending_connection_request');
    if (req) {
      activePendingRequest = req;
      incomingAlert.style.display = 'flex';
      alertRequesterId.textContent = `Node: ${req.node_id.substring(0, 16)}... (${req.endpoint})`;
    } else {
      activePendingRequest = null;
      incomingAlert.style.display = 'none';
    }
  } catch (e) {
    // Silently continue
  }
}

btnAcceptRequest.addEventListener('click', async () => {
  if (activePendingRequest) {
    try {
      await invoke('respond_connection_request', {
        nodeId: activePendingRequest.node_id,
        accept: true,
      });
      incomingAlert.style.display = 'none';
      setTimeout(updatePeers, 400);
      setTimeout(updateKnownDevices, 400);
    } catch (e) {
      alert('Accept error: ' + e);
    }
  }
});

btnDeclineRequest.addEventListener('click', async () => {
  if (activePendingRequest) {
    try {
      await invoke('respond_connection_request', {
        nodeId: activePendingRequest.node_id,
        accept: false,
      });
      incomingAlert.style.display = 'none';
    } catch (e) {
      alert('Decline error: ' + e);
    }
  }
});

async function updateKnownDevices() {
  try {
    const devices = await invoke('get_known_devices');
    if (!devices || devices.length === 0) {
      knownCount.textContent = '0 saved';
      knownTbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="5">No saved devices yet. Connected machines will be remembered here for easy reconnect.</td>
        </tr>`;
      return;
    }

    knownCount.textContent = `${devices.length} saved`;
    knownTbody.innerHTML = devices.map(d => `
      <tr>
        <td class="font-mono"><strong>${d.alias}</strong></td>
        <td class="font-mono text-truncate" style="max-width: 140px;">${d.node_id}</td>
        <td class="font-mono">${d.endpoint}</td>
        <td>
          <div class="perm-group">
            <label class="perm-label" title="Allow Remote Desktop"><input type="checkbox" ${d.allow_rdp !== false ? 'checked' : ''} onchange="toggleDevicePerm('${d.node_id}', 'rdp', this.checked)"> RDP</label>
            <label class="perm-label" title="Allow GhostDrop file transfer"><input type="checkbox" ${d.allow_ghostdrop !== false ? 'checked' : ''} onchange="toggleDevicePerm('${d.node_id}', 'drop', this.checked)"> Drop</label>
            <label class="perm-label" title="Temporary session: revoke on disconnect"><input type="checkbox" ${d.temporary_session ? 'checked' : ''} onchange="toggleDevicePerm('${d.node_id}', 'temp', this.checked)"> Temp</label>
          </div>
        </td>
        <td>
          <button class="btn-connect-sm" onclick="connectKnown('${d.node_id}', '${d.endpoint}')">Connect</button>
          <button class="btn-forget-sm" onclick="forgetDevice('${d.node_id}')">Forget</button>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    // Silently continue
  }
}

window.toggleDevicePerm = async function(nodeId, permType, value) {
  try {
    const devices = await invoke('get_known_devices') || [];
    const dev = devices.find(d => d.node_id === nodeId);
    if (!dev) return;

    let allowRdp = dev.allow_rdp !== false;
    let allowDrop = dev.allow_ghostdrop !== false;
    let temporary = !!dev.temporary_session;

    if (permType === 'rdp') allowRdp = value;
    if (permType === 'drop') allowDrop = value;
    if (permType === 'temp') temporary = value;

    await invoke('update_device_permissions', {
      nodeId,
      allowRdp,
      allowGhostdrop: allowDrop,
      temporarySession: temporary,
    });
  } catch (e) {
    console.error('Permission update error:', e);
  }
};

window.connectKnown = async function(nodeId, endpoint) {
  try {
    await invoke('request_device_connect', {
      targetNodeId: nodeId,
      targetEndpoint: endpoint,
    });
    alert('Connection request sent to ' + endpoint + '. Waiting for peer to accept.');
  } catch (e) {
    alert('Connection request error: ' + e);
  }
};

window.forgetDevice = async function(nodeId) {
  try {
    await invoke('remove_known_device', { nodeId });
    updateKnownDevices();
  } catch (e) {
    alert('Forget error: ' + e);
  }
};

window.launchRdp = async function(nodeId) {
  try {
    await invoke('launch_rdp', { nodeId: nodeId });
  } catch (e) {
    alert('RDP launch error: ' + e);
  }
};

// GhostChat Implementation
const modalChat = document.getElementById('modal-chat');
const chatPeerIdEl = document.getElementById('chat-peer-id');
const chatMessagesContainer = document.getElementById('chat-messages-container');
const chatInputText = document.getElementById('chat-input-text');
const btnSendChat = document.getElementById('btn-send-chat');
let activeChatPeer = null;
let chatPollInterval = null;

window.openChat = function(nodeId) {
  activeChatPeer = nodeId;
  chatPeerIdEl.textContent = 'Node: ' + nodeId;
  modalChat.style.display = 'flex';
  chatMessagesContainer.innerHTML = '<div class="chat-empty">Loading secure chat...</div>';
  updateChatMessages();

  if (chatPollInterval) clearInterval(chatPollInterval);
  chatPollInterval = setInterval(updateChatMessages, 1200);
  setTimeout(() => chatInputText.focus(), 100);
};

async function updateChatMessages() {
  if (!activeChatPeer || modalChat.style.display === 'none') return;
  try {
    const msgs = await invoke('get_chat_messages', { targetNodeId: activeChatPeer }) || [];
    if (msgs.length === 0) {
      chatMessagesContainer.innerHTML = '<div class="chat-empty">No messages yet. Send an encrypted message below.</div>';
      return;
    }

    const html = msgs.map(m => {
      const isOut = m.recipient === activeChatPeer;
      const date = new Date(m.timestamp_secs * 1000);
      const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      return `
        <div class="chat-bubble ${isOut ? 'outgoing' : 'incoming'}">
          <div class="chat-text">${escapeHtml(m.text)}</div>
          <div class="chat-meta">${timeStr}</div>
        </div>
      `;
    }).join('');

    chatMessagesContainer.innerHTML = html;
    chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
  } catch (e) {
    console.error('Chat error:', e);
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function sendCurrentChatMessage() {
  const text = chatInputText.value.trim();
  if (!text || !activeChatPeer) return;

  chatInputText.value = '';
  try {
    await invoke('send_chat_message', {
      targetNodeId: activeChatPeer,
      text: text,
    });
    updateChatMessages();
  } catch (e) {
    alert('Failed to send message: ' + e);
  }
}

btnSendChat.addEventListener('click', sendCurrentChatMessage);
chatInputText.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    sendCurrentChatMessage();
  }
});

// Toast Notification Helper
const toastAlert = document.getElementById('toast-alert');
let toastTimer = null;
function showToast(msg) {
  if (toastTimer) clearTimeout(toastTimer);
  toastAlert.textContent = msg;
  toastAlert.style.display = 'block';
  toastTimer = setTimeout(() => {
    toastAlert.style.display = 'none';
  }, 3500);
}

// Clipboard Sync Logic
window.sendClipboardTo = async function(nodeId) {
  try {
    const text = await navigator.clipboard.readText();
    if (!text) {
      showToast('Clipboard is empty');
      return;
    }
    await invoke('send_clipboard_to_peer', {
      targetNodeId: nodeId,
      text: text,
    });
    showToast(`Clipboard sent to ${nodeId.substring(0, 8)}... (${text.length} chars)`);
  } catch (e) {
    showToast('Clipboard send error: ' + e);
  }
};

async function checkIncomingClipboard() {
  try {
    const clip = await invoke('get_incoming_clipboard');
    if (clip && clip.text) {
      const autoSync = chkAutoClipboard ? chkAutoClipboard.checked : true;
      if (autoSync) {
        await navigator.clipboard.writeText(clip.text);
        showToast(`Clipboard auto-synced from ${clip.sender.substring(0, 8)}... (${clip.text.length} chars)`);
      } else {
        showToast(`Received clipboard from ${clip.sender.substring(0, 8)}... (Auto-sync disabled)`);
      }
    }
  } catch (e) {
    // Silently continue
  }
}

// Exit Node (Internet Gateway) Logic
window.toggleExitNode = async function(nodeId) {
  try {
    if (activeExitNode === nodeId) {
      await invoke('set_exit_node', { targetNodeId: null });
      activeExitNode = null;
      showToast('Exit Node Gateway deactivated (Direct Internet)');
    } else {
      await invoke('set_exit_node', { targetNodeId: nodeId });
      activeExitNode = nodeId;
      showToast(`Routing Internet through Exit Node ${nodeId.substring(0, 8)}...`);
    }
    updatePeers();
  } catch (e) {
    alert('Exit Node error: ' + e);
  }
};

async function updateExitNodeStatus() {
  try {
    const status = await invoke('get_exit_node_status');
    if (status) {
      activeExitNode = status.target_node_id;
      if (chkAllowExitNode) chkAllowExitNode.checked = !!status.allow_sharing;
    }
  } catch (e) {
    // Silently continue
  }
}

// System Preferences & Settings
const chkAutostart = document.getElementById('chk-autostart');
const chkAutoClipboard = document.getElementById('chk-auto-clipboard');
const chkAllowExitNode = document.getElementById('chk-allow-exit-node');

async function initSettings() {
  try {
    const enabled = await invoke('get_autostart');
    if (chkAutostart) chkAutostart.checked = !!enabled;

    const autoClip = await invoke('get_auto_clipboard');
    if (chkAutoClipboard) chkAutoClipboard.checked = autoClip !== false;

    updateExitNodeStatus();
  } catch (e) {
    console.error('Settings init error:', e);
  }
}

if (chkAutostart) {
  chkAutostart.addEventListener('change', async function() {
    try {
      await invoke('set_autostart', { enable: this.checked });
      showToast('Autostart configuration updated');
    } catch (e) {
      alert('Failed to update startup configuration: ' + e);
    }
  });
}

if (chkAutoClipboard) {
  chkAutoClipboard.addEventListener('change', async function() {
    try {
      await invoke('set_auto_clipboard', { enable: this.checked });
      showToast('Clipboard sync preference saved');
    } catch (e) {
      alert('Clipboard settings error: ' + e);
    }
  });
}

if (chkAllowExitNode) {
  chkAllowExitNode.addEventListener('change', async function() {
    try {
      await invoke('set_allow_exit_node', { allow: this.checked });
      showToast(this.checked ? 'Exit Node sharing enabled' : 'Exit Node sharing disabled');
    } catch (e) {
      alert('Exit node sharing error: ' + e);
    }
  });
}

// Auto-Updater Check
const updateAlert = document.getElementById('update-alert');
const updateTag = document.getElementById('update-tag');
const btnCloseUpdate = document.getElementById('btn-close-update');
const btnUpdateLink = document.getElementById('btn-update-link');

async function checkForUpdates() {
  try {
    const res = await fetch('https://api.github.com/repos/NeyorDEV/ghostmesh/releases/latest');
    if (res.ok) {
      const data = await res.json();
      const latestTag = data.tag_name || '';
      const currentVer = 'v0.2.5';
      if (latestTag && latestTag !== currentVer && latestTag > currentVer) {
        updateTag.textContent = latestTag;
        updateAlert.style.display = 'flex';
      }
    }
  } catch (e) {
    // Silently continue if offline
  }
}

btnCloseUpdate.addEventListener('click', () => {
  updateAlert.style.display = 'none';
});

btnRefresh.addEventListener('click', () => {
  btnRefresh.classList.add('spinning');
  setTimeout(() => btnRefresh.classList.remove('spinning'), 600);
  updateStatus();
  updatePeers();
  updateTransferMonitor();
  updateSyncStatus();
  updateKnownDevices();
  updateIncomingRequests();
  updateExitNodeStatus();
  checkForUpdates();
});

// Initialize
initSettings();
checkForUpdates();
updateStatus();
updatePeers();
updateTransferMonitor();
updateSyncStatus();
updateKnownDevices();
updateIncomingRequests();
setInterval(updateStatus, 3000);
setInterval(updatePeers, 2000);
setInterval(updateTransferMonitor, 400);
setInterval(updateSyncStatus, 2500);
setInterval(updateKnownDevices, 4000);
setInterval(updateIncomingRequests, 1500);
setInterval(checkIncomingClipboard, 1500);
