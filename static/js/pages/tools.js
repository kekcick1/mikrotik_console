App.addPage('interfaces', 'Interfaces', '🔌', {
  init: function() {
    var self = this;
    var c = App.el('page-interfaces');
    c.innerHTML = '<div class="card panel"><div class="iface-toolbar"><div class="iface-head"><div class="iface-title-wrap"><h2 id="ifaceTitle" style="margin:0">Interfaces</h2><span id="sshStatus" class="ssh-indicator reconnect">SSH reconnect</span></div><div class="iface-actions"><button id="ifaceRefreshBtn" class="auto" type="button">Refresh</button><button id="ifaceTestBtn" class="secondary auto" type="button">Test SSH</button><button id="ifaceDisconnectBtn" class="secondary auto" type="button">Disconnect</button></div></div></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Port</th><th>Type</th><th>MTU</th><th>Comment</th><th>Status</th><th>Action</th></tr></thead><tbody id="ifaceBody"></tbody></table></div></div>';
    App.el('ifaceRefreshBtn').onclick = function() { self.loadInterfaces(); };
    App.el('ifaceTestBtn').onclick = function() { self.testSsh(); };
    App.el('ifaceDisconnectBtn').onclick = function() { self.disconnect(); };
  },
  onEnter: function() {
    if (App.state.selectedDevice) this.loadInterfaces();
  },
  onDeviceChanged: function(device) {
    App.el('ifaceTitle').textContent = device ? 'Interfaces: ' + device.name : 'Interfaces';
    App.el('ifaceBody').innerHTML = '';
    this.setSshStatus('reconnect');
    if (device) this.loadInterfaces();
  },
  setSshStatus: function(st, idleSec, queueDepth) {
    var el = App.el('sshStatus');
    var safe = st === 'active' ? 'active' : 'reconnect';
    el.classList.remove('active', 'reconnect'); el.classList.add(safe);
    var idle = typeof idleSec === 'number' ? ' • idle ' + idleSec + 's' : '';
    var queue = (queueDepth||0) > 0 ? ' • queue ' + queueDepth : '';
    el.textContent = 'SSH ' + safe + idle + queue;
  },
  loadInterfaces: async function() {
    var dev = App.state.selectedDevice; if (!dev) return;
    try {
      var data = await App.api('/api/devices/' + dev.id + '/interfaces');
      this.renderInterfaces(data);
      await this.loadSshStatus();
    } catch (e) { App.status(e.message, true); }
  },
  loadSshStatus: async function() {
    var dev = App.state.selectedDevice;
    if (!dev) { this.setSshStatus('reconnect'); return; }
    try {
      var out = await App.api('/api/devices/' + dev.id + '/ssh-status');
      this.setSshStatus(out.status, out.idle_seconds, out.queue_depth || 0);
    } catch(e) { this.setSshStatus('reconnect'); }
  },
  testSsh: async function() {
    var dev = App.state.selectedDevice;
    if (!dev) return App.status('Select a device');
    try {
      var out = await App.api('/api/devices/' + dev.id + '/test', { method: 'POST' });
      App.status('SSH OK: ' + (out.output || ''));
      await this.loadSshStatus();
    } catch (e) { App.status(e.message, true); }
  },
  disconnect: async function() {
    var dev = App.state.selectedDevice;
    if (!dev) return App.status('Select a device');
    try {
      await App.api('/api/devices/' + dev.id + '/disconnect', { method: 'POST' });
      App.status('Disconnected: ' + dev.name);
      await this.loadSshStatus();
    } catch (e) { App.status(e.message, true); }
  },
  renderInterfaces: function(items) {
    var self = this;
    var tbody = App.el('ifaceBody');
    tbody.innerHTML = '';
    var unique = [];
    var seen = {};
    for (var k = 0; k < items.length; k++) {
      var it = items[k];
      var key = [it.name || '', it.port || '', it.type || '', it.mtu || '', it.comment || '', !!it.disabled, !!it.running].join('|');
      if (seen[key]) continue;
      seen[key] = true;
      unique.push(it);
    }
    for (var i = 0; i < unique.length; i++) {
      (function(iface) {
        var tr = document.createElement('tr');
        var badge = iface.disabled
          ? '<span class="badge bad">disabled</span>'
          : (iface.running ? '<span class="badge ok">running</span>' : '<span class="badge warn">up/no-link</span>');
        tr.innerHTML = '<td><strong>' + iface.name + '</strong></td><td>' + (iface.port||'-') + '</td><td>' + (iface.type||'-') + '</td><td>' + (iface.mtu||'-') + '</td><td>' + (iface.comment||'-') + '</td><td>' + badge + '</td><td></td>';
        var td = tr.querySelector('td:last-child');
        var actions = document.createElement('div');
        actions.className = 'iface-row-actions';
        var actBtn = document.createElement('button');
        actBtn.textContent = iface.disabled ? 'Enable' : 'Disable';
        actBtn.className = iface.disabled ? '' : 'danger';
        actBtn.disabled = !App.can('operator');
        actBtn.onclick = async function() {
          var dev = App.state.selectedDevice; if (!dev) return;
          await App.api('/api/devices/' + dev.id + '/interfaces/' + encodeURIComponent(iface.name), { method: 'POST', body: JSON.stringify({ disabled: !iface.disabled }) });
          self.loadInterfaces();
        };
        actions.appendChild(actBtn);
        var editBtn = document.createElement('button');
        editBtn.textContent = 'Edit'; editBtn.className = 'secondary';
        editBtn.disabled = !App.can('operator');
        editBtn.onclick = function() { self.openEdit(iface); };
        actions.appendChild(editBtn);
        td.appendChild(actions);
        tbody.appendChild(tr);
      })(unique[i]);
    }
  },
  openEdit: function(iface) {
    App.state.editingInterfaceName = iface.name;
    App.el('ifaceEditCurrent').textContent = 'Interface: ' + iface.name;
    App.el('ifaceEditNewName').value = '';
    App.el('ifaceEditMtu').value = iface.mtu || '';
    App.el('ifaceEditComment').value = iface.comment || '';
    App.el('ifaceEditBackdrop').classList.remove('hidden');
    App.el('ifaceEditModal').classList.remove('hidden');
  },
});

(function() {
  function closeEdit() {
    App.state.editingInterfaceName = '';
    App.el('ifaceEditBackdrop').classList.add('hidden');
    App.el('ifaceEditModal').classList.add('hidden');
  }
  App.el('ifaceEditCancel').onclick = closeEdit;
  App.el('ifaceEditBackdrop').onclick = closeEdit;
  App.el('ifaceEditSave').onclick = async function() {
    var dev = App.state.selectedDevice;
    var ifName = App.state.editingInterfaceName;
    if (!dev || !ifName) return;
    var payload = {};
    var newName = App.el('ifaceEditNewName').value.trim();
    var mtuRaw = App.el('ifaceEditMtu').value.trim();
    var comment = App.el('ifaceEditComment').value.trim();
    if (newName) payload.new_name = newName;
    if (mtuRaw) payload.mtu = Number(mtuRaw);
    if (comment) payload.comment = comment;
    if (!Object.keys(payload).length) return App.status('No changes');
    try {
      await App.api('/api/devices/' + dev.id + '/interfaces/' + encodeURIComponent(ifName) + '/edit', { method: 'POST', body: JSON.stringify(payload) });
      App.status('Interface updated: ' + ifName);
      closeEdit();
      var p = App.pages.find(function(p) { return p.id === 'interfaces'; });
      if (p && p.loadInterfaces) p.loadInterfaces();
    } catch (e) { App.status(e.message, true); }
  };
})();

App.addPage('terminal', 'Terminal', '💻', {
  minRole: 'operator',
  _history: [],
  _historyIndex: -1,
  _historyDraft: '',
  init: function() {
    var self = this;
    var c = App.el('page-terminal');
    c.innerHTML = '<div class="grid-2"><div class="card panel"><div class="row"><h2 style="margin:0">Terminal</h2><button id="termClearBtn" class="secondary auto" type="button">Clear</button></div><textarea id="termInput" placeholder="Example: /interface print terse"></textarea><div class="row"><button id="termRunBtn" type="button">Run on selected</button><button id="termBroadcastPreview" class="secondary" type="button">Dry-run broadcast</button><button id="termBroadcastConfirm" class="success" type="button" disabled>Confirm broadcast</button></div><div id="termOutput" class="terminal"></div></div><div class="stack"><div class="card panel"><div class="row"><h2 style="margin:0">SSH Diagnostics</h2><button id="termRefreshDiag" class="secondary auto" type="button">Refresh</button></div><div class="diag-grid" id="termDiagGrid"><div class="diag-item"><div class="diag-label">Status</div><div class="diag-value" id="diagStatus">-</div></div><div class="diag-item"><div class="diag-label">RouterOS</div><div class="diag-value" id="diagRos">-</div></div><div class="diag-item"><div class="diag-label">RTT</div><div class="diag-value" id="diagRtt">-</div></div><div class="diag-item"><div class="diag-label">Reconnect Count</div><div class="diag-value" id="diagReconnect">-</div></div><div class="diag-item"><div class="diag-label">Queue Depth</div><div class="diag-value" id="diagQueue">-</div></div><div class="diag-item"><div class="diag-label">Last Error</div><div class="diag-value" id="diagError">-</div></div><div class="diag-item"><div class="diag-label">Last Success</div><div class="diag-value" id="diagSuccess">-</div></div></div></div></div></div>';
    App.el('termClearBtn').onclick = function() { App.el('termOutput').innerHTML = ''; };
    App.el('termRunBtn').onclick = function() { self.runCommand(); };
    App.el('termBroadcastPreview').onclick = function() { self.broadcastPreview(); };
    App.el('termBroadcastConfirm').onclick = function() { self.broadcastConfirm(); };
    App.el('termRefreshDiag').onclick = function() { self.loadDiagnostics(); };
    App.el('termInput').addEventListener('keydown', function(e) {
      self.onTerminalKeydown(e);
    });
    App.el('termInput').addEventListener('input', function() {
      if (App.state.pendingBroadcast) {
        App.state.pendingBroadcast = null;
        App.el('termBroadcastConfirm').disabled = true;
      }
    });
  },
  onEnter: function() {
    if (App.state.selectedDevice) this.loadDiagnostics();
  },
  onDeviceChanged: function(device) {
    this.resetDiag();
    var rosEl = App.el('diagRos');
    if (rosEl) rosEl.textContent = (device && device.ros_version) ? device.ros_version : '-';
    if (device) this.loadDiagnostics();
  },
  onTerminalKeydown: function(e) {
    if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
    var input = App.el('termInput');
    if (!input) return;

    var value = input.value;
    var pos = input.selectionStart;
    var firstLine = value.lastIndexOf('\n', Math.max(0, pos - 1)) === -1;
    var nextBreak = value.indexOf('\n', pos);
    var lastLine = nextBreak === -1;

    if (e.key === 'ArrowUp' && !firstLine) return;
    if (e.key === 'ArrowDown' && !lastLine) return;
    if (!this._history.length) return;

    e.preventDefault();
    if (this._historyIndex === -1) {
      this._historyDraft = input.value;
      this._historyIndex = this._history.length;
    }

    if (e.key === 'ArrowUp') {
      if (this._historyIndex > 0) this._historyIndex -= 1;
    } else if (e.key === 'ArrowDown') {
      if (this._historyIndex < this._history.length) this._historyIndex += 1;
    }

    if (this._historyIndex >= this._history.length) {
      input.value = this._historyDraft;
      this._historyIndex = -1;
    } else {
      input.value = this._history[this._historyIndex] || '';
    }
    input.selectionStart = input.selectionEnd = input.value.length;
  },
  pushHistory: function(command) {
    var cmd = String(command || '').trim();
    if (!cmd) return;
    if (!this._history.length || this._history[this._history.length - 1] !== cmd) {
      this._history.push(cmd);
    }
    if (this._history.length > 200) this._history.shift();
    this._historyIndex = -1;
    this._historyDraft = '';
  },
  termWrite: function(line, isError) {
    var stamp = new Date().toLocaleTimeString();
    var div = document.createElement('div');
    div.textContent = '[' + stamp + '] ' + line;
    if (isError) div.style.color = '#ff8f85';
    var out = App.el('termOutput');
    out.appendChild(div);
    out.scrollTop = out.scrollHeight;
  },
  resetDiag: function() {
    ['diagStatus','diagRos','diagRtt','diagReconnect','diagQueue','diagError','diagSuccess'].forEach(function(id) {
      var e = App.el(id); if (e) e.textContent = '-';
    });
  },
  loadDiagnostics: async function() {
    var dev = App.state.selectedDevice;
    if (!dev) { this.resetDiag(); return; }
    try {
      var d = await App.api('/api/devices/' + dev.id + '/ssh-diagnostics');
      App.el('diagStatus').textContent = d.status || '-';
      App.el('diagRos').textContent = d.ros_version || (dev.ros_version || '-');
      App.el('diagRtt').textContent = typeof d.rtt_ms === 'number' ? d.rtt_ms + ' ms' : '-';
      App.el('diagReconnect').textContent = '' + (d.reconnect_count || 0);
      App.el('diagQueue').textContent = '' + (d.queue_depth || 0);
      App.el('diagError').textContent = d.last_error || '-';
      App.el('diagSuccess').textContent = d.last_success_at || '-';
    } catch(e) { this.resetDiag(); }
  },
  runCommand: async function() {
    var dev = App.state.selectedDevice;
    if (!dev) return App.status('Select a device');
    var command = App.el('termInput').value.trim();
    if (!command) return App.status('Enter a command');
    this.pushHistory(command);
    this.termWrite('> [' + dev.name + '] ' + command);
    try {
      var out = await App.api('/api/devices/' + dev.id + '/terminal', { method: 'POST', body: JSON.stringify({ command: command }) });
      this.termWrite(out.output || '(empty)');
      await this.loadDiagnostics();
    } catch (e) { App.status(e.message, true); this.termWrite(e.message, true); }
  },
  broadcastPreview: async function() {
    var command = App.el('termInput').value.trim();
    if (!command) return App.status('Enter a command');
    this.pushHistory(command);
    try {
      var out = await App.api('/api/terminal/broadcast/preview', { method: 'POST', body: JSON.stringify({ command: command }) });
      App.state.pendingBroadcast = { command: command, token: out.confirm_token, expiresIn: out.confirm_ttl_seconds, targets: out.targets || [] };
      App.el('termBroadcastConfirm').disabled = false;
      this.termWrite('> [ALL PREVIEW] ' + command);
      this.termWrite('Targets: ' + App.state.pendingBroadcast.targets.length + ', TTL: ' + App.state.pendingBroadcast.expiresIn + 's');
      for (var i = 0; i < Math.min(App.state.pendingBroadcast.targets.length, 20); i++) {
        var t = App.state.pendingBroadcast.targets[i];
        this.termWrite(' - ' + t.name + ' (queue=' + t.queue_depth + ')');
      }
    } catch (e) { App.status(e.message, true); this.termWrite(e.message, true); }
  },
  broadcastConfirm: async function() {
    var pb = App.state.pendingBroadcast;
    if (!pb) return App.status('Run dry-run first');
    try {
      var out = await App.api('/api/terminal/broadcast/execute', { method: 'POST', body: JSON.stringify({ command: pb.command, confirm_token: pb.token }) });
      this.termWrite('> [ALL EXECUTE] ' + pb.command);
      for (var i = 0; i < out.results.length; i++) {
        var r = out.results[i];
        if (r.ok) this.termWrite('[' + r.name + '] OK\n' + (r.output || '(empty)'));
        else this.termWrite('[' + r.name + '] ERROR: ' + r.error, true);
      }
    } catch (e) { App.status(e.message, true); this.termWrite(e.message, true);
    } finally { App.state.pendingBroadcast = null; App.el('termBroadcastConfirm').disabled = true; }
  },
});

App.addPage('backups', 'Backups', '💾', {
  _bulkResults: [],
  _bulkFilter: 'all',
  init: function() {
    var self = this;
    var c = App.el('page-backups');
    c.innerHTML = '<div class="stack"><div class="card panel"><div class="row"><h2 style="margin:0">Device Backups</h2><button id="backupCaptureBtn" class="auto" type="button">Create Backup</button><button id="backupCaptureAllBtn" class="secondary auto" type="button">Backup All Reachable</button><button id="backupRefreshBtn" class="secondary auto" type="button">Refresh</button></div><div class="row" style="margin-top:8px"><input id="backupUploadFile" type="file" accept=".rsc,.txt" /><button id="backupUploadBtn" class="secondary auto" type="button">Upload</button></div><div id="backupBulkSummary" class="status"></div><div class="row" style="margin-top:4px"><span class="muted auto">Bulk result filter:</span><button id="backupBulkFilterAll" class="secondary auto bulk-filter-btn" type="button">All</button><button id="backupBulkFilterOk" class="secondary auto bulk-filter-btn" type="button">OK</button><button id="backupBulkFilterFail" class="secondary auto bulk-filter-btn" type="button">FAIL</button></div><div id="backupBulkResults" class="backup-bulk-list"></div><div id="backupList" class="backup-list" style="margin-top:10px"></div></div><div class="card panel" id="systemBackupCard"><div class="row"><h2 style="margin:0">System Backup (Full)</h2><button id="systemBackupCreateBtn" class="auto" type="button">Create Full Backup</button><button id="systemBackupRefreshBtn" class="secondary auto" type="button">Refresh</button></div><div id="systemBackupStatus" class="status"></div><div id="systemBackupList" class="backup-list" style="margin-top:10px"></div></div></div>';
    App.el('backupRefreshBtn').onclick = function() { self.loadBackups(); };
    App.el('backupCaptureBtn').onclick = function() { self.capture(); };
    App.el('backupCaptureAllBtn').onclick = function() { self.captureAllSequential(); };
    App.el('backupUploadBtn').onclick = function() { self.upload(); };
    App.el('backupBulkFilterAll').onclick = function() { self.setBulkFilter('all'); };
    App.el('backupBulkFilterOk').onclick = function() { self.setBulkFilter('ok'); };
    App.el('backupBulkFilterFail').onclick = function() { self.setBulkFilter('fail'); };
    App.el('systemBackupRefreshBtn').onclick = function() { self.loadSystemBackups(); };
    App.el('systemBackupCreateBtn').onclick = function() { self.createSystemBackup(); };
    this.setBulkFilter('all');
    if (!App.can('operator')) {
      App.el('backupCaptureBtn').disabled = true;
      App.el('backupCaptureAllBtn').disabled = true;
      App.el('backupUploadBtn').disabled = true;
    }
    if (!App.can('admin')) {
      App.el('systemBackupCard').classList.add('hidden');
    }
  },
  setBulkFilter: function(filter) {
    this._bulkFilter = filter;
    var allBtn = App.el('backupBulkFilterAll');
    var okBtn = App.el('backupBulkFilterOk');
    var failBtn = App.el('backupBulkFilterFail');
    if (allBtn) allBtn.classList.toggle('active', filter === 'all');
    if (okBtn) okBtn.classList.toggle('active', filter === 'ok');
    if (failBtn) failBtn.classList.toggle('active', filter === 'fail');
    this.renderBulkResults();
  },
  renderBulkResults: function() {
    var resultList = App.el('backupBulkResults');
    if (!resultList) return;
    var details = this._bulkResults || [];
    if (!details.length) {
      resultList.innerHTML = '<div class="muted">No bulk backup results yet.</div>';
      return;
    }

    var filtered = details.filter(function(r) {
      if (this._bulkFilter === 'ok') return !!r.ok;
      if (this._bulkFilter === 'fail') return !r.ok;
      return true;
    }.bind(this));

    if (!filtered.length) {
      resultList.innerHTML = '<div class="muted">No entries for selected filter.</div>';
      return;
    }

    var html = '';
    for (var j = 0; j < filtered.length; j++) {
      var r = filtered[j];
      var statusClass = r.status === 'pending' ? 'warn' : (r.ok ? 'ok' : 'bad');
      var statusText = r.status === 'pending' ? 'PENDING' : (r.ok ? 'OK' : 'FAIL');
      html += '<div class="item bulk-item"><span class="badge ' + statusClass + '">' + statusText + '</span><strong style="margin-left:8px">' + r.name + '</strong><div class="item-meta" style="margin-top:6px">' + r.message + '</div></div>';
    }
    resultList.innerHTML = html;
  },
  onEnter: function() {
    if (App.state.selectedDevice) this.loadBackups();
    if (App.can('admin')) this.loadSystemBackups();
    this.renderBulkResults();
  },
  onDeviceChanged: function(device) { App.el('backupList').innerHTML = ''; if (device) this.loadBackups(); },
  loadBackups: async function() {
    var dev = App.state.selectedDevice; if (!dev) return;
    try { var items = await App.api('/api/devices/' + dev.id + '/backups'); this.renderBackups(items); }
    catch (e) { App.status(e.message, true); }
  },
  renderBackups: function(items) {
    var self = this;
    var list = App.el('backupList');
    list.innerHTML = '';
    if (!items.length) { list.innerHTML = '<div class="muted">No backups yet</div>'; return; }
    for (var i = 0; i < items.length; i++) {
      (function(b) {
        var item = document.createElement('div'); item.className = 'item';
        item.innerHTML = '<strong>' + b.name + '</strong><div class="item-meta">' + (b.created_at || '') + '</div>';
        var row = document.createElement('div'); row.className = 'row';
        var dl = document.createElement('button'); dl.className = 'secondary auto'; dl.textContent = 'Download';
        dl.onclick = function() { self.downloadBackup(b); };
        var restore = document.createElement('button'); restore.className = 'danger auto'; restore.textContent = 'Restore';
        restore.disabled = !App.can('operator');
        restore.onclick = async function() {
          var dev = App.state.selectedDevice;
          if (!dev || !confirm('Restore ' + b.name + '?')) return;
          try { await App.api('/api/devices/' + dev.id + '/backups/' + b.id + '/restore', { method: 'POST' }); App.status('Restore OK: ' + b.name); }
          catch (e) { App.status(e.message, true); }
        };
        var del = document.createElement('button'); del.className = 'secondary auto'; del.textContent = 'Delete';
        del.disabled = !App.can('operator');
        del.onclick = async function() {
          var dev = App.state.selectedDevice;
          if (!dev || !confirm('Delete backup ' + b.name + '?')) return;
          try { await App.api('/api/devices/' + dev.id + '/backups/' + b.id, { method: 'DELETE' }); App.status('Deleted: ' + b.name); self.loadBackups(); }
          catch (e) { App.status(e.message, true); }
        };
        row.appendChild(dl); row.appendChild(restore); row.appendChild(del);
        item.appendChild(row); list.appendChild(item);
      })(items[i]);
    }
  },
  downloadBackup: async function(b) {
    var dev = App.state.selectedDevice; if (!dev) return;
    try {
      var headers = {};
      if (App.state.token) headers.Authorization = 'Bearer ' + App.state.token;
      var resp = await fetch('/api/devices/' + dev.id + '/backups/' + b.id + '/download', { headers: headers });
      if (resp.status === 401) { App.logout(); throw new Error('Session expired'); }
      if (!resp.ok) throw new Error('Download failed');
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a'); a.href = url; a.download = b.name || 'backup.rsc';
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      App.status('Downloaded: ' + b.name);
    } catch (e) { App.status(e.message, true); }
  },
  capture: async function() {
    var dev = App.state.selectedDevice;
    if (!dev) return App.status('Select a device');
    try {
      var out = await App.api('/api/devices/' + dev.id + '/backups/capture', { method: 'POST' });
      App.status('Backup created: ' + out.backup.name);
      this.loadBackups();
    } catch (e) { App.status(e.message, true); }
  },
  captureAllSequential: async function() {
    if (!App.can('operator')) return;
    var st = App.el('backupBulkSummary');
    var resultList = App.el('backupBulkResults');
    if (st) st.textContent = '';
    if (resultList) resultList.innerHTML = '';

    await App.loadDevices();
    var devices = (App.state.devices || []).slice();
    if (!devices.length) {
      if (st) st.textContent = 'No devices available for backup.';
      return;
    }

    var total = devices.length;
    var ok = 0;
    var failed = 0;
    var details = devices.map(function(d) {
      return { ok: false, status: 'pending', name: d.name, message: 'Waiting in queue...' };
    });
    this._bulkResults = details;
    this.renderBulkResults();

    var allBtn = App.el('backupCaptureAllBtn');
    var oneBtn = App.el('backupCaptureBtn');
    if (allBtn) allBtn.disabled = true;
    if (oneBtn) oneBtn.disabled = true;

    try {
      for (var i = 0; i < devices.length; i++) {
        var d = devices[i];
        details[i].status = 'pending';
        details[i].message = 'Running backup (' + (i + 1) + '/' + total + ')...';
        this.renderBulkResults();
        if (st) st.textContent = 'Backing up ' + d.name + ' (' + (i + 1) + '/' + total + ')...';
        try {
          var out = await App.api('/api/devices/' + d.id + '/backups/capture', { method: 'POST' });
          ok += 1;
          details[i].ok = true;
          details[i].status = 'done';
          details[i].message = out && out.backup ? out.backup.name : 'created';
        } catch (e) {
          failed += 1;
          details[i].ok = false;
          details[i].status = 'done';
          details[i].message = e.message;
        }
        this.renderBulkResults();
      }
    } finally {
      if (allBtn) allBtn.disabled = !App.can('operator');
      if (oneBtn) oneBtn.disabled = !App.can('operator');
    }

    var summary = 'Bulk backup finished. OK=' + ok + ', FAILED=' + failed + ', TOTAL=' + total;
    if (st) st.textContent = summary;
    this._bulkResults = details;
    this.renderBulkResults();
    App.status(summary, failed > 0);

    if (App.state.selectedDevice) this.loadBackups();
  },
  upload: async function() {
    var dev = App.state.selectedDevice;
    if (!dev) return App.status('Select a device');
    var fileInput = App.el('backupUploadFile');
    var file = fileInput.files && fileInput.files[0];
    if (!file) return App.status('Select a file');
    try {
      var content = await file.text();
      await App.api('/api/devices/' + dev.id + '/backups/upload', { method: 'POST', body: JSON.stringify({ name: file.name, content: content }) });
      App.status('Uploaded: ' + file.name);
      fileInput.value = '';
      this.loadBackups();
    } catch (e) { App.status(e.message, true); }
  },
  createSystemBackup: async function() {
    if (!App.can('admin')) return;
    var st = App.el('systemBackupStatus');
    if (st) st.textContent = 'Creating full backup...';
    try {
      var out = await App.api('/api/system/backup/create', { method: 'POST' });
      if (st) st.textContent = 'Created: ' + out.name + ' (' + out.size_bytes + ' bytes)';
      await this.loadSystemBackups();
    } catch (e) {
      if (st) st.textContent = e.message;
      App.status(e.message, true);
    }
  },
  loadSystemBackups: async function() {
    if (!App.can('admin')) return;
    try {
      var items = await App.api('/api/system/backup/list');
      this.renderSystemBackups(items);
    } catch (e) {
      App.status(e.message, true);
    }
  },
  renderSystemBackups: function(items) {
    var self = this;
    var list = App.el('systemBackupList');
    if (!list) return;
    list.innerHTML = '';
    if (!items.length) {
      list.innerHTML = '<div class="muted">No system backups yet</div>';
      return;
    }
    for (var i = 0; i < items.length; i++) {
      (function(b) {
        var item = document.createElement('div');
        item.className = 'item';
        item.innerHTML = '<strong>' + b.name + '</strong><div class="item-meta">' + b.created_at + ' • ' + b.size_bytes + ' bytes</div>';
        var row = document.createElement('div');
        row.className = 'row';
        var dl = document.createElement('button');
        dl.className = 'secondary auto';
        dl.textContent = 'Download';
        dl.onclick = function() { self.downloadSystemBackup(b.name); };
        var restore = document.createElement('button');
        restore.className = 'danger auto';
        restore.textContent = 'Restore Full';
        restore.onclick = async function() {
          if (!confirm('Restore full system from ' + b.name + '? This replaces current DB and backup files.')) return;
          await self.restoreSystemBackup(b.name);
        };
        row.appendChild(dl);
        row.appendChild(restore);
        item.appendChild(row);
        list.appendChild(item);
      })(items[i]);
    }
  },
  downloadSystemBackup: async function(name) {
    try {
      var headers = {};
      if (App.state.token) headers.Authorization = 'Bearer ' + App.state.token;
      var resp = await fetch('/api/system/backup/' + encodeURIComponent(name) + '/download', { headers: headers });
      if (resp.status === 401) { App.logout(); throw new Error('Session expired'); }
      if (!resp.ok) throw new Error('Download failed');
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a'); a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      App.status('Downloaded system backup: ' + name);
    } catch (e) { App.status(e.message, true); }
  },
  restoreSystemBackup: async function(name) {
    var st = App.el('systemBackupStatus');
    if (st) st.textContent = 'Restoring full system backup...';
    try {
      var out = await App.api('/api/system/backup/' + encodeURIComponent(name) + '/restore', { method: 'POST' });
      if (st) st.textContent = 'Restored: ' + out.restored_from;
      App.status('System restore completed: ' + out.restored_from);
      await App.loadDevices();
      await this.loadSystemBackups();
      this.loadBackups();
    } catch (e) {
      if (st) st.textContent = e.message;
      App.status(e.message, true);
    }
  },
});

App.addPage('admin', 'Admin', '🛡️', {
  minRole: 'operator',
  init: function() {
    var self = this;
    var c = App.el('page-admin');
    c.innerHTML = '<div class="grid-2"><div class="stack"><div class="card panel" id="adminUsersCard"><h2>Users</h2><form id="adminUserForm" class="row"><input name="username" placeholder="username" required /><input name="password" type="password" placeholder="password" required /><select name="role" required><option value="viewer">viewer</option><option value="operator">operator</option><option value="admin">admin</option></select><button type="submit" class="auto">Add</button></form><div id="adminUserList" class="user-list" style="margin-top:8px"></div></div><div class="card panel" id="adminSystemCard"><div class="row"><h2 style="margin:0">System Backup</h2><button id="adminSystemRefresh" class="secondary auto" type="button">Refresh</button></div><div class="row" style="margin-top:8px"><button id="adminSystemCreate" type="button">Create Full Backup</button></div><div id="adminSystemStatus" class="status"></div><div id="adminSystemBackupList" class="backup-list" style="margin-top:8px"></div></div></div><div class="card panel"><div class="row"><h2 style="margin:0">Recent Activity</h2><button id="adminRefreshAudit" class="secondary auto" type="button">Refresh</button></div><div id="adminAuditList" class="audit-list" style="margin-top:8px"></div></div></div>';
    if (!App.can('admin')) { var uc = App.el('adminUsersCard'); if (uc) uc.classList.add('hidden'); }
    if (!App.can('admin')) { var sc = App.el('adminSystemCard'); if (sc) sc.classList.add('hidden'); }
    App.el('adminUserForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      try {
        var fd = new FormData(e.target);
        var payload = Object.fromEntries(fd.entries());
        await App.api('/api/users', { method: 'POST', body: JSON.stringify(payload) });
        e.target.reset(); self.loadUsers(); self.loadAudit();
      } catch (err) { App.status(err.message, true); }
    });
    App.el('adminRefreshAudit').onclick = function() { self.loadAudit(); };
    App.el('adminSystemRefresh').onclick = function() { self.loadSystemBackups(); };
    App.el('adminSystemCreate').onclick = function() { self.createSystemBackup(); };
  },
  onEnter: async function() {
    if (App.can('admin')) await this.loadUsers();
    if (App.can('admin')) await this.loadSystemBackups();
    await this.loadAudit();
  },
  loadUsers: async function() {
    if (!App.can('admin')) return;
    try { var items = await App.api('/api/users'); this.renderUsers(items); }
    catch (e) { App.status(e.message, true); }
  },
  renderUsers: function(items) {
    var self = this;
    var list = App.el('adminUserList'); list.innerHTML = '';
    for (var i = 0; i < items.length; i++) {
      (function(u) {
        var item = document.createElement('div'); item.className = 'item';
        item.innerHTML = '<strong>' + u.username + '</strong><div class="item-meta">' + u.role + ' • ' + u.created_at + '</div>';
        var row = document.createElement('div'); row.className = 'row';
        var del = document.createElement('button'); del.className = 'secondary auto'; del.textContent = 'Delete';
        del.disabled = App.state.currentUser && u.username === App.state.currentUser.username;
        del.onclick = async function() {
          if (!confirm('Delete user ' + u.username + '?')) return;
          await App.api('/api/users/' + u.id, { method: 'DELETE' });
          self.loadUsers(); self.loadAudit();
        };
        var cpw = document.createElement('button'); cpw.className = 'secondary auto'; cpw.textContent = 'Change PW';
        cpw.onclick = function() { App.openPwModal(u.id, u.username); };
        row.appendChild(del); row.appendChild(cpw); item.appendChild(row); list.appendChild(item);
      })(items[i]);
    }
  },
  loadAudit: async function() {
    if (!App.can('operator')) return;
    try {
      var items = await App.api('/api/audit?limit=150');
      var list = App.el('adminAuditList'); list.innerHTML = '';
      if (!items.length) { list.innerHTML = '<div class="muted">No recent activity</div>'; return; }
      for (var i = 0; i < items.length; i++) {
        var a = items[i];
        var div = document.createElement('div'); div.className = 'item';
        div.innerHTML = '<strong>' + a.action + '</strong><div class="item-meta">' + a.created_at + ' • ' + a.username + ' (' + a.role + ')' + (a.device_name ? ' • ' + a.device_name : '') + '</div><div class="item-meta">' + (a.details || '') + '</div>';
        list.appendChild(div);
      }
    } catch (e) { App.status(e.message, true); }
  },
  createSystemBackup: async function() {
    if (!App.can('admin')) return;
    var st = App.el('adminSystemStatus');
    if (st) st.textContent = 'Creating backup...';
    try {
      var out = await App.api('/api/system/backup/create', { method: 'POST' });
      if (st) st.textContent = 'Created: ' + out.name + ' (' + out.size_bytes + ' bytes)';
      await this.loadSystemBackups();
      await this.loadAudit();
    } catch (e) {
      if (st) st.textContent = e.message;
      App.status(e.message, true);
    }
  },
  loadSystemBackups: async function() {
    if (!App.can('admin')) return;
    try {
      var items = await App.api('/api/system/backup/list');
      this.renderSystemBackups(items);
    } catch (e) {
      App.status(e.message, true);
    }
  },
  renderSystemBackups: function(items) {
    var self = this;
    var list = App.el('adminSystemBackupList');
    if (!list) return;
    list.innerHTML = '';
    if (!items.length) {
      list.innerHTML = '<div class="muted">No system backups yet</div>';
      return;
    }
    for (var i = 0; i < items.length; i++) {
      (function(b) {
        var item = document.createElement('div');
        item.className = 'item';
        item.innerHTML = '<strong>' + b.name + '</strong><div class="item-meta">' + b.created_at + ' • ' + b.size_bytes + ' bytes</div>';
        var row = document.createElement('div');
        row.className = 'row';
        var dl = document.createElement('button');
        dl.className = 'secondary auto';
        dl.textContent = 'Download';
        dl.onclick = function() { self.downloadSystemBackup(b.name); };
        row.appendChild(dl);
        item.appendChild(row);
        list.appendChild(item);
      })(items[i]);
    }
  },
  downloadSystemBackup: async function(name) {
    try {
      var headers = {};
      if (App.state.token) headers.Authorization = 'Bearer ' + App.state.token;
      var resp = await fetch('/api/system/backup/' + encodeURIComponent(name) + '/download', { headers: headers });
      if (resp.status === 401) { App.logout(); throw new Error('Session expired'); }
      if (!resp.ok) throw new Error('Download failed');
      var blob = await resp.blob();
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a'); a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
      App.status('Downloaded: ' + name);
    } catch (e) {
      App.status(e.message, true);
    }
  },
});
