App.addPage('devices', 'Devices', '🖥️', {
  _filterText: '',
  init: function() {
    var self = this;
    var c = App.el('page-devices');
    c.innerHTML = '<div class="grid-2"><div class="stack"><div class="card panel" id="devicesAddCard"><h2>Add Device</h2><form id="devAddForm"><input name="name" placeholder="Name" required /><input name="host" placeholder="IP / DNS" required /><input name="port" type="number" value="22" required /><input name="username" placeholder="SSH user" required /><input name="password" type="password" placeholder="SSH password" required /><button type="submit">Save</button></form></div><div class="card panel"><h2>Import / Export</h2><input id="devBulkFile" type="file" accept=".txt,.csv,.list" /><input id="devBulkUser" placeholder="SSH user for imported devices" /><input id="devBulkPass" type="password" placeholder="SSH password for imported devices" /><input id="devBulkPort" type="number" value="22" min="1" max="65535" placeholder="SSH port" /><label class="inline-check"><input id="devBulkUpdate" type="checkbox" />Update existing</label><input id="devBulkServerPath" value="/home/user/ip _ M" placeholder="Server file path" /><div class="row"><button id="devImportFileBtn" type="button">Import File</button><button id="devImportServerBtn" class="secondary" type="button">Import Server Path</button></div><div style="margin-top:10px"><button id="devExportBtn" class="secondary" type="button">Export Device List</button></div></div><div class="card panel"><div class="row"><h2 style="margin:0">SSH Concurrency</h2><button id="devSshConcurrencyRefresh" class="secondary auto" type="button">Refresh</button></div><div class="muted">Global limit for simultaneous SSH operations across all routers.</div><div class="row"><input id="devSshConcurrencyLimit" type="number" min="1" max="32" value="4" /><button id="devSshConcurrencySave" class="auto" type="button">Apply</button></div><div id="devSshConcurrencyRuntime" class="status"></div></div></div><div class="card panel"><div class="row"><h2 style="margin:0">Device List</h2><button id="devRefreshVersionsBtn" class="secondary auto" type="button">Refresh Versions</button><button id="devDeleteSelectedBtn" class="danger auto" type="button">Delete Selected</button><button id="devRefreshBtn" class="secondary auto" type="button">Refresh</button></div><input id="devSearch" placeholder="Search by name, host, port, username or version" /><div id="devList" class="device-list" style="margin-top:8px"></div><div id="devStatus" class="status"></div></div></div>';

    App.el('devAddForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      var fd = new FormData(e.target);
      var payload = Object.fromEntries(fd.entries());
      payload.port = Number(payload.port || 22);
      try {
        await App.api('/api/devices', { method: 'POST', body: JSON.stringify(payload) });
        e.target.reset(); e.target.port.value = 22;
        await App.loadDevices(); self.renderDevices();
        App.status('Device added');
      } catch (err) { App.status(err.message, true); }
    });
    App.el('devRefreshBtn').onclick = async function() { await App.loadDevices(); self.renderDevices(); };
    App.el('devRefreshVersionsBtn').onclick = async function() { await self.refreshVersions(); };
    App.el('devSshConcurrencyRefresh').onclick = async function() { await self.loadSshConcurrency(); };
    App.el('devSshConcurrencySave').onclick = async function() { await self.saveSshConcurrency(); };
    App.el('devDeleteSelectedBtn').onclick = async function() {
      var dev = App.state.selectedDevice;
      if (!dev) return App.status('Select a device first');
      if (!App.can('operator')) return App.status('Delete requires operator/admin role', true);
      if (!confirm('Delete ' + dev.name + '?')) return;
      try {
        await self.deleteDevice(dev);
        App.status('Deleted: ' + dev.name);
      } catch (err) {
        App.status(err.message, true);
      }
    };
    App.el('devExportBtn').onclick = async function() {
      try {
        var headers = {};
        if (App.state.token) headers.Authorization = 'Bearer ' + App.state.token;
        var resp = await fetch('/api/devices/export', { headers: headers });
        if (!resp.ok) throw new Error('Export failed');
        var blob = await resp.blob();
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a'); a.href = url; a.download = 'mikrotik-devices-export.txt';
        document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
        App.status('Exported');
      } catch (e) { App.status(e.message, true); }
    };
    App.el('devImportFileBtn').onclick = function() { self.doImport(false); };
    App.el('devImportServerBtn').onclick = function() { self.doImport(true); };
    App.el('devSearch').addEventListener('input', function() {
      self._filterText = String(this.value || '').trim().toLowerCase();
      self.renderDevices();
    });

    App.el('devList').onclick = async function(e) {
      var target = e.target;
      if (target && target.nodeType === 3) target = target.parentElement;
      if (!target || !target.closest) return;
      var item = target.closest('.device-item');
      if (!item) return;

      var id = Number(item.dataset.deviceId || 0);
      if (!id) return;

      var device = App.state.devices.find(function(x) { return x.id === id; }) || null;
      if (!device) return;

      var delBtn = target.closest('button[data-action="delete-device"]');
      var editBtn = target.closest('button[data-action="edit-device"]');

      if (editBtn) {
        e.preventDefault();
        e.stopPropagation();
        if (!App.can('operator')) return;
        try {
          editBtn.disabled = true;
          await self.editDevice(device);
        } catch (err) {
          App.status(err.message, true);
        } finally {
          editBtn.disabled = false;
        }
        return;
      }

      if (delBtn) {
        e.preventDefault();
        e.stopPropagation();
        if (!App.can('operator')) return;
        if (!confirm('Delete ' + device.name + '?')) return;
        try {
          delBtn.disabled = true;
          await self.deleteDevice(device);
          App.status('Deleted: ' + device.name);
        } catch (err) {
          App.status(err.message, true);
        } finally {
          delBtn.disabled = false;
        }
        return;
      }

      App.selectDevice(device);
      self.renderDevices();
    };
  },
  doImport: async function(fromServer) {
    var self = this;
    var username = App.el('devBulkUser').value.trim();
    var password = App.el('devBulkPass').value;
    var port = Number(App.el('devBulkPort').value || 22);
    var updateExisting = App.el('devBulkUpdate').checked;
    if (!username || !password) return App.status('Provide SSH username and password');
    var body = { username: username, password: password, port: port, update_existing: updateExisting };
    if (fromServer) {
      var serverPath = App.el('devBulkServerPath').value.trim();
      if (!serverPath) return App.status('Provide server file path');
      body.server_path = serverPath;
    } else {
      var file = App.el('devBulkFile').files && App.el('devBulkFile').files[0];
      if (!file) return App.status('Select import file');
      body.content = await file.text();
    }
    try {
      var out = await App.api('/api/devices/import', { method: 'POST', body: JSON.stringify(body) });
      App.status('Import: created=' + out.created + ', updated=' + (out.updated||0) + ', skipped=' + out.skipped + ', errors=' + (out.errors||[]).length);
      await App.loadDevices(); self.renderDevices();
    } catch (e) { App.status(e.message, true); }
  },
  onEnter: function() {
    this.renderDevices();
    this.loadSshConcurrency();
    if (!App.can('operator')) {
      var addCard = App.el('devicesAddCard');
      if (addCard) addCard.classList.add('hidden');
      var ib = App.el('devImportFileBtn'); if (ib) ib.disabled = true;
      var is = App.el('devImportServerBtn'); if (is) is.disabled = true;
    }
    var saveBtn = App.el('devSshConcurrencySave');
    if (saveBtn) saveBtn.disabled = !App.can('admin');
  },
  renderDevices: function() {
    var list = App.el('devList');
    list.innerHTML = '';
    var filter = this._filterText;
    var visibleCount = 0;
    for (var i = 0; i < App.state.devices.length; i++) {
      (function(d) {
        var searchable = (d.name + ' ' + d.host + ' ' + d.port + ' ' + d.username + ' ' + (d.ros_version || '')).toLowerCase();
        if (filter && searchable.indexOf(filter) === -1) return;
        visibleCount += 1;
        var box = document.createElement('div');
        box.className = 'device-item' + (App.state.selectedDevice && App.state.selectedDevice.id === d.id ? ' active' : '');
        box.dataset.deviceId = String(d.id);
        var version = d.ros_version || 'unknown';
        box.innerHTML = '<strong>' + d.name + '</strong><div class="muted">' + d.host + ':' + d.port + ' • ' + d.username + '</div><div class="muted">RouterOS: ' + version + '</div>';
        if (App.can('operator')) {
          var edit = document.createElement('button');
          edit.textContent = 'Edit'; edit.className = 'secondary'; edit.style.marginTop = '6px';
          edit.type = 'button';
          edit.dataset.action = 'edit-device';
          box.appendChild(edit);

          var del = document.createElement('button');
          del.textContent = 'Delete'; del.className = 'secondary'; del.style.marginTop = '6px';
          del.type = 'button';
          del.dataset.action = 'delete-device';
          box.appendChild(del);
        }
        list.appendChild(box);
      })(App.state.devices[i]);
    }
    var st = App.el('devStatus');
    if (st) st.textContent = 'Devices: ' + visibleCount + ' / ' + App.state.devices.length;
  },
  deleteDevice: async function(device) {
    await App.api('/api/devices/' + device.id, { method: 'DELETE' });
    if (App.state.selectedDevice && App.state.selectedDevice.id === device.id) {
      App.selectDevice(null);
    }
    await App.loadDevices();
    this.renderDevices();
  },
  refreshVersions: async function() {
    if (!App.can('operator')) return App.status('Version refresh requires operator/admin role', true);
    var btn = App.el('devRefreshVersionsBtn');
    if (btn) btn.disabled = true;
    try {
      var out = await App.api('/api/devices/refresh-versions', { method: 'POST' });
      var ok = (out.results || []).filter(function(x) { return x.ok; }).length;
      var failed = (out.results || []).length - ok;
      App.status('RouterOS versions refreshed: OK=' + ok + ', FAILED=' + failed, failed > 0);
      await App.loadDevices();
      this.renderDevices();
    } catch (e) {
      App.status(e.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  },
  loadSshConcurrency: async function() {
    try {
      var out = await App.api('/api/devices/ssh-concurrency');
      var limitEl = App.el('devSshConcurrencyLimit');
      if (limitEl) limitEl.value = String(out.limit || 1);
      var rt = App.el('devSshConcurrencyRuntime');
      if (rt) rt.textContent = 'Limit: ' + out.limit + ' • Active: ' + out.active + ' • Waiting: ' + out.waiting;
    } catch (e) {
      App.status(e.message, true);
    }
  },
  saveSshConcurrency: async function() {
    if (!App.can('admin')) return App.status('Only admin can change SSH concurrency limit', true);
    var btn = App.el('devSshConcurrencySave');
    var input = App.el('devSshConcurrencyLimit');
    var next = Number((input && input.value) || 0);
    if (!Number.isFinite(next) || next < 1 || next > 32) return App.status('Limit must be between 1 and 32', true);
    if (btn) btn.disabled = true;
    try {
      var out = await App.api('/api/devices/ssh-concurrency', { method: 'PUT', body: JSON.stringify({ limit: next }) });
      var rt = App.el('devSshConcurrencyRuntime');
      if (rt) rt.textContent = 'Limit: ' + out.limit + ' • Active: ' + out.active + ' • Waiting: ' + out.waiting;
      App.status('SSH concurrency limit updated to ' + out.limit);
    } catch (e) {
      App.status(e.message, true);
    } finally {
      if (btn) btn.disabled = !App.can('admin');
    }
  },
  editDevice: async function(device) {
    var name = prompt('Device name:', device.name || '');
    if (name === null) return;
    name = String(name).trim();
    if (!name) return App.status('Name is required', true);

    var host = prompt('Host (IP/DNS):', device.host || '');
    if (host === null) return;
    host = String(host).trim();
    if (!host) return App.status('Host is required', true);

    var portRaw = prompt('SSH port:', String(device.port || 22));
    if (portRaw === null) return;
    var port = Number(String(portRaw).trim() || '22');
    if (!Number.isFinite(port) || port < 1 || port > 65535) return App.status('Port must be 1..65535', true);

    var username = prompt('SSH username:', device.username || '');
    if (username === null) return;
    username = String(username).trim();
    if (!username) return App.status('Username is required', true);

    var password = prompt('New SSH password (leave empty to keep current):', '');
    if (password === null) return;

    var payload = {
      name: name,
      host: host,
      port: port,
      username: username,
    };
    if (String(password).length > 0) payload.password = String(password);

    await App.api('/api/devices/' + device.id, { method: 'PUT', body: JSON.stringify(payload) });
    App.status('Updated: ' + name);
    await App.loadDevices();
    this.renderDevices();
  },
});
