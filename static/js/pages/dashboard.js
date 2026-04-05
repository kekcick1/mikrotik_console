App.addPage('dashboard', 'Dashboard', '📊', {
  _connectTicker: null,
  _connectStatusPoller: null,
  _statusUnsubscribe: null,
  _liveSummary: null,
  _liveItems: [],
  _healthWorkerEnabled: null,
  _manualConnected: {},
  _routerLogsCache: {},
  _lastStatusCache: {},
  init: function() {
    this._statusUnsubscribe = null;
    this._liveSummary = null;
    this._liveItems = [];
    this._healthWorkerEnabled = null;
    this._manualConnected = {};
    this._routerLogsCache = {};
    this._lastStatusCache = {};
    var c = App.el('page-dashboard');
    c.innerHTML = '<div class="stats-row" id="dashStats"></div><div class="card panel" style="margin-bottom:14px"><div class="row"><h2 style="margin:0">MikroTik Connection Center</h2><button id="dashReloadDevices" class="secondary auto" type="button">Refresh Devices</button></div><div class="row"><button id="dashConnectBtn" type="button">Connect/Test SSH</button><button id="dashConnectApiBtn" class="secondary" type="button">Connect API</button><button id="dashOpenInterfaces" class="secondary" type="button">Interfaces</button><button id="dashOpenTerminal" class="secondary" type="button">Terminal</button><button id="dashOpenBackups" class="secondary" type="button">Backups</button><button id="dashDisconnectBtn" class="secondary" type="button">Disconnect</button></div><div id="dashConnStatus" class="status"></div></div><div style="margin-top:16px"><div class="card panel"><div class="row"><h2 style="margin:0">Router Logs (MikroTik)</h2><button id="dashRefreshRouterLogs" class="secondary auto" type="button">Refresh</button></div><div id="dashRouterLogs" class="terminal" style="margin-top:8px;min-height:180px;max-height:260px"></div></div></div>';
    var insights = document.createElement('div');
    insights.className = 'card panel';
    insights.style.marginTop = '14px';
    insights.innerHTML = '<div class="row"><h2 style="margin:0">Device Status</h2><span id="dashHealthWorkerState" class="muted auto"></span><button id="dashToggleHealthWorker" class="secondary auto" type="button">Auto Check</button><button id="dashRefreshMetrics" class="secondary auto" type="button">Refresh</button></div><div class="stats-row" id="dashSysStats" style="margin-top:8px"></div><div id="dashDevStatusGrid" class="dev-status-grid" style="margin-top:10px"></div>';
    c.appendChild(insights);
    App.el('dashRefreshRouterLogs').onclick = this.loadRouterLogs.bind(this);
    App.el('dashRefreshMetrics').onclick = this.loadSystemMetrics.bind(this);
    App.el('dashToggleHealthWorker').onclick = this.toggleHealthWorker.bind(this);
    App.el('dashReloadDevices').onclick = async function() {
      await App.loadDevices();
      var p = App.pages.find(function(x) { return x.id === 'dashboard'; });
      if (p) {
        p.renderStats();
        await p.loadSystemMetrics();
        await p.loadRouterLogs();
      }
    };
    App.el('dashConnectBtn').onclick = this.connectSelected.bind(this);
    App.el('dashConnectApiBtn').onclick = this.connectSelectedApi.bind(this);
    App.el('dashDisconnectBtn').onclick = this.disconnectSelected.bind(this);
    App.el('dashOpenInterfaces').onclick = function() {
      if (!App.state.selectedDevice) return App.status('Select a device first');
      App.navigate('interfaces');
    };
    App.el('dashOpenTerminal').onclick = function() {
      if (!App.state.selectedDevice) return App.status('Select a device first');
      if (!App.can('operator')) return App.status('Terminal is available for operator/admin', true);
      App.navigate('terminal');
    };
    App.el('dashOpenBackups').onclick = function() {
      if (!App.state.selectedDevice) return App.status('Select a device first');
      App.navigate('backups');
    };
  },
  onEnter: async function() {
    this.ensureStatusSubscription();
    this.renderStats();
    this.renderConnectionState();
    await this.loadHealthWorkerRuntime();
    await this.loadRouterLogs();
    await this.loadSystemMetrics();
  },
  onDeviceChanged: function() {
    this.renderStats();
    this.renderConnectionState();
    this.loadRouterLogs();
  },
  ensureStatusSubscription: function() {
    var self = this;
    if (self._statusUnsubscribe) return;
    self._statusUnsubscribe = App.subscribeStatusStream(function(payload) {
      self.onStatusStreamPayload(payload);
    });
  },
  onStatusStreamPayload: function(payload) {
    if (!payload || !Array.isArray(payload.items)) return;
    this._liveItems = payload.items.slice();
    this._liveSummary = payload.summary || null;

    var page = App.el('page-dashboard');
    if (!page || !page.classList.contains('active')) return;

    var incoming = payload.items.map(this.mergeWithCachedStatus.bind(this));
    this.renderDeviceStatuses(incoming);
    if (payload.summary) {
      this.renderSystemSummary(payload.summary);
    }
  },
  refreshConnectedDeviceStatuses: async function() {
    if (!this._liveItems.length) {
      try {
        var items = await App.api('/api/devices/status-overview?lite=1');
        for (var i = 0; i < items.length; i++) {
          this.applyStatusToExistingCard(this.mergeWithCachedStatus(items[i]));
        }
      } catch (_) {}
      return;
    }
    var connectedIds = Object.keys(this._manualConnected || {});
    if (!connectedIds.length) return;
    for (var j = 0; j < connectedIds.length; j++) {
      var id = Number(connectedIds[j]);
      var row = this._liveItems.find(function(x) { return Number(x.id) === id; });
      if (row) this.applyStatusToExistingCard(this.mergeWithCachedStatus(row));
    }
  },
  refreshOneDeviceStatus: async function(deviceId, full) {
    var id = Number(deviceId || 0);
    if (!id) return;
    var q = full ? '?lite=0' : '?lite=1';
    var row = await App.api('/api/devices/' + id + '/status-overview' + q);
    this.applyStatusToExistingCard(this.mergeWithCachedStatus(row));
  },
  mergeWithCachedStatus: function(d) {
    var id = Number(d && d.id);
    if (!id) return d;
    var cached = this._lastStatusCache[id] || {};
    var merged = Object.assign({}, cached, d);
    if (!d.uptime && cached.uptime) merged.uptime = cached.uptime;
    if (!d.ros_version && cached.ros_version) merged.ros_version = cached.ros_version;
    this._lastStatusCache[id] = {
      uptime: merged.uptime || cached.uptime || null,
      ros_version: merged.ros_version || cached.ros_version || null,
    };
    return merged;
  },
  renderStats: function() {
    var el = App.el('dashStats');
    var total = App.state.devices.length;
    var sel = App.state.selectedDevice ? App.state.selectedDevice.name : 'None';
    var role = App.state.currentUser ? App.state.currentUser.role : '-';
    App.clearNode(el);

    function appendStatCard(value, label) {
      var card = App.createEl('div', { className: 'stat-card' });
      card.appendChild(App.createEl('div', { className: 'stat-value', text: value }));
      card.appendChild(App.createEl('div', { className: 'stat-label', text: label }));
      el.appendChild(card);
    }

    appendStatCard(total, 'Devices');
    appendStatCard(sel, 'Selected');
    appendStatCard(role, 'Role');
  },
  renderConnectionState: function() {
    var s = App.el('dashConnStatus');
    if (!s) return;
    if (!App.state.selectedDevice) {
      s.textContent = 'Select a MikroTik device to connect and start management';
      s.style.color = 'var(--muted)';
      return;
    }
    s.textContent = 'Selected: ' + App.state.selectedDevice.name + ' (' + App.state.selectedDevice.host + ':' + App.state.selectedDevice.port + ')';
    s.style.color = 'var(--muted)';
  },
  renderHealthWorkerControls: function(runtime) {
    var stateEl = App.el('dashHealthWorkerState');
    var toggleBtn = App.el('dashToggleHealthWorker');
    if (!stateEl || !toggleBtn) return;

    if (!runtime) {
      stateEl.textContent = 'Auto check: unavailable';
      toggleBtn.disabled = true;
      toggleBtn.textContent = 'Auto Check';
      return;
    }

    this._healthWorkerEnabled = !!runtime.enabled;
    stateEl.textContent = 'Auto check: ' + (runtime.enabled ? 'ON' : 'OFF') + ' • every ' + runtime.interval_seconds + 's';
    toggleBtn.textContent = runtime.enabled ? 'Disable Auto Check' : 'Enable Auto Check';
    toggleBtn.disabled = !App.can('admin');
  },
  loadHealthWorkerRuntime: async function() {
    try {
      var runtime = await App.api('/api/system/health-worker');
      this.renderHealthWorkerControls(runtime);
    } catch (e) {
      var stateEl = App.el('dashHealthWorkerState');
      var toggleBtn = App.el('dashToggleHealthWorker');
      if (stateEl) stateEl.textContent = 'Auto check: unavailable';
      if (toggleBtn) toggleBtn.disabled = true;
    }
  },
  toggleHealthWorker: async function() {
    if (!App.can('admin')) return App.status('Only admin can toggle auto status check', true);
    if (this._healthWorkerEnabled == null) await this.loadHealthWorkerRuntime();
    var next = !(this._healthWorkerEnabled === true);
    var toggleBtn = App.el('dashToggleHealthWorker');
    if (toggleBtn) toggleBtn.disabled = true;
    try {
      var runtime = await App.api('/api/system/health-worker', {
        method: 'PUT',
        body: JSON.stringify({ enabled: next }),
      });
      this.renderHealthWorkerControls(runtime);
      App.status('Auto status check ' + (runtime.enabled ? 'enabled' : 'disabled'));
    } catch (e) {
      App.status(e.message, true);
      await this.loadHealthWorkerRuntime();
    } finally {
      var btn = App.el('dashToggleHealthWorker');
      if (btn) btn.disabled = !App.can('admin');
    }
  },
  setSelectedDashboardDevice: function(device) {
    if (!device) return null;
    App.selectDevice(device);
    this.renderStats();
    this.renderConnectionState();
    return device;
  },
  setConnectButtonsBusy: function(busy) {
    var connectBtn = App.el('dashConnectBtn');
    var connectApiBtn = App.el('dashConnectApiBtn');
    var disconnectBtn = App.el('dashDisconnectBtn');
    if (connectBtn) connectBtn.disabled = !!busy;
    if (connectApiBtn) connectApiBtn.disabled = !!busy;
    if (disconnectBtn) disconnectBtn.disabled = !!busy;
  },
  markManualConnected: function(deviceId, connected) {
    if (!deviceId) return;
    if (connected) this._manualConnected[deviceId] = true;
    else delete this._manualConnected[deviceId];
  },
  isManualConnected: function(deviceId) {
    return !!this._manualConnected[deviceId];
  },
  startConnectTicker: function(deviceName) {
    this.stopConnectTicker();
    var s = App.el('dashConnStatus');
    if (!s) return;
    var frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    var idx = 0;
    var started = Date.now();
    var timeoutSec = 10;
    this._connectTicker = setInterval(function() {
      var elapsed = (Date.now() - started) / 1000;
      var left = Math.max(0, timeoutSec - elapsed).toFixed(1);
      s.textContent = frames[idx % frames.length] + ' Connecting to ' + deviceName + '... ~' + left + 's';
      s.style.color = 'var(--warn)';
      idx += 1;
    }, 120);
  },
  stopConnectTicker: function() {
    if (this._connectTicker) {
      clearInterval(this._connectTicker);
      this._connectTicker = null;
    }
  },
  startConnectStatusPolling: function() {
    this.stopConnectStatusPolling();
  },
  stopConnectStatusPolling: function() {
    if (this._connectStatusPoller) {
      clearInterval(this._connectStatusPoller);
      this._connectStatusPoller = null;
    }
  },
  connectDevice: async function(device) {
    var dev = this.setSelectedDashboardDevice(device);
    var s = App.el('dashConnStatus');
    if (!dev) {
      if (s) { s.textContent = 'Select a device first'; s.style.color = 'var(--warn)'; }
      return;
    }
    this.setConnectButtonsBusy(true);
    this.startConnectTicker(dev.name);
    this.startConnectStatusPolling();
    try {
      var out = await App.api('/api/devices/' + dev.id + '/test', { method: 'POST' });
      this.markManualConnected(dev.id, true);
      this.stopConnectTicker();
      if (s) {
        s.textContent = 'Connected: ' + dev.name + ' | ' + (out.output || 'SSH OK') + (out.ros_version ? ' | ROS ' + out.ros_version : '');
        s.style.color = 'var(--ok)';
      }
      App.status('Connected to ' + dev.name);
    } catch (e) {
      if (s) {
        s.textContent = 'Connection failed: ' + e.message;
        s.style.color = 'var(--bad)';
      }
      App.status(e.message, true);
    } finally {
      this.stopConnectTicker();
      this.stopConnectStatusPolling();
      this.setConnectButtonsBusy(false);
      if (dev && dev.id) await this.refreshOneDeviceStatus(dev.id, true);
    }
  },
  disconnectDevice: async function(device) {
    var dev = this.setSelectedDashboardDevice(device);
    var s = App.el('dashConnStatus');
    if (!dev) {
      if (s) { s.textContent = 'Select a device first'; s.style.color = 'var(--warn)'; }
      return;
    }
    if (!App.can('operator')) {
      if (s) { s.textContent = 'Disconnect requires operator or admin role'; s.style.color = 'var(--bad)'; }
      return;
    }
    try {
      await App.api('/api/devices/' + dev.id + '/disconnect', { method: 'POST' });
      this.markManualConnected(dev.id, false);
      if (s) {
        s.textContent = 'Disconnected from ' + dev.name;
        s.style.color = 'var(--warn)';
      }
      App.status('Disconnected from ' + dev.name);
    } catch (e) {
      if (s) {
        s.textContent = 'Disconnect failed: ' + e.message;
        s.style.color = 'var(--bad)';
      }
      App.status(e.message, true);
    } finally {
      if (dev && dev.id) await this.refreshOneDeviceStatus(dev.id, false);
    }
  },
  connectSelected: async function() {
    await this.connectDevice(App.state.selectedDevice);
  },
  connectDeviceApi: async function(device) {
    var dev = this.setSelectedDashboardDevice(device);
    var s = App.el('dashConnStatus');
    if (!dev) {
      if (s) { s.textContent = 'Select a device first'; s.style.color = 'var(--warn)'; }
      return;
    }
    var apiPortRaw = prompt('RouterOS API port (8728 for plain, 8729 for TLS):', '8728');
    if (apiPortRaw === null) return;
    var apiPort = Number(String(apiPortRaw).trim() || '8728');
    if (!Number.isFinite(apiPort) || apiPort < 1 || apiPort > 65535) {
      if (s) { s.textContent = 'Invalid API port'; s.style.color = 'var(--bad)'; }
      return;
    }
    var useTls = confirm('Use API TLS/SSL (typically port 8729)?');

    this.setConnectButtonsBusy(true);
    this.startConnectTicker(dev.name);
    try {
      var out = await App.api('/api/devices/' + dev.id + '/test-api?api_port=' + encodeURIComponent(String(apiPort)) + '&api_ssl=' + (useTls ? '1' : '0'), { method: 'POST' });
      this.markManualConnected(dev.id, true);
      this.stopConnectTicker();
      if (s) {
        s.textContent = 'API connected: ' + dev.name + ' | identity: ' + (out.identity || 'unknown') + (out.ros_version ? ' | ROS ' + out.ros_version : '') + ' | port: ' + out.api_port + (out.api_ssl ? ' TLS' : '');
        s.style.color = 'var(--ok)';
      }
      App.status('API connected to ' + dev.name);
    } catch (e) {
      if (s) {
        s.textContent = 'API connection failed: ' + e.message;
        s.style.color = 'var(--bad)';
      }
      App.status(e.message, true);
    } finally {
      this.stopConnectTicker();
      this.setConnectButtonsBusy(false);
      if (dev && dev.id) await this.refreshOneDeviceStatus(dev.id, true);
    }
  },
  connectSelectedApi: async function() {
    await this.connectDeviceApi(App.state.selectedDevice);
  },
  disconnectSelected: async function() {
    await this.disconnectDevice(App.state.selectedDevice);
  },
  renderQA: function() {},
  loadRouterLogs: async function() {
    var el = App.el('dashRouterLogs');
    if (!el) return;
    var dev = App.state.selectedDevice;
    if (!dev) {
      el.textContent = 'Select a device to view MikroTik logs.';
      return;
    }
    if (!App.can('operator')) {
      el.textContent = 'Router logs are available for operator/admin.';
      return;
    }

    // Never auto-connect on simple device switch from Device Status grid.
    if (!this.isManualConnected(dev.id)) {
      var cached = this._routerLogsCache[dev.id];
      if (cached) {
        el.textContent = cached;
      } else {
        el.textContent = 'Not connected to this device yet. Press Connect/Test to fetch live logs.';
      }
      return;
    }

    el.textContent = 'Loading router logs...';
    try {
      var out = await App.api('/api/devices/' + dev.id + '/router-logs');
      var text = (out && out.output ? String(out.output) : '').trim();
      el.textContent = text || 'No router logs available.';
      this._routerLogsCache[dev.id] = el.textContent;
      // Keep the latest log lines visible without manual scrolling.
      el.scrollTop = el.scrollHeight;
    } catch (e) {
      el.textContent = 'Failed to load router logs: ' + e.message;
    }
  },
  loadSystemMetrics: async function() {
    var self = this;
    var stats = App.el('dashSysStats');
    var grid = App.el('dashDevStatusGrid');
    if (!stats || !grid) return;
    try {
      var items = await App.api('/api/devices/status-overview');
      items = items.map(function(x) { return self.mergeWithCachedStatus(x); });
      var summary = {
        devices_total: items.length,
        active_sessions: items.filter(function(d) { return (d.session_state || d.status) === 'active'; }).length,
        online: items.filter(function(d) { return d.health_state === 'online'; }).length,
        degraded: items.filter(function(d) { return d.health_state === 'degraded'; }).length,
        offline: items.filter(function(d) { return d.health_state === 'offline'; }).length,
        unknown: items.filter(function(d) { return d.health_state === 'unknown'; }).length,
        stale: items.filter(function(d) { return !!d.stale; }).length,
        errors: items.filter(function(d) { return !!d.last_error; }).length,
      };
      self.renderSystemSummary(summary);
      self.renderDeviceStatuses(items);
    } catch (e) {
      App.clearNode(stats);
      stats.appendChild(App.createEl('div', { className: 'muted', text: e.message }));
      App.clearNode(grid);
    }
  },
  renderSystemSummary: function(summary) {
    var stats = App.el('dashSysStats');
    if (!stats) return;
    App.clearNode(stats);

    function appendStatCard(value, label, borderColor, valueColor) {
      var card = App.createEl('div', { className: 'stat-card' });
      if (borderColor) card.style.borderColor = borderColor;
      var valueEl = App.createEl('div', { className: 'stat-value', text: value });
      if (valueColor) valueEl.style.color = valueColor;
      card.appendChild(valueEl);
      card.appendChild(App.createEl('div', { className: 'stat-label', text: label }));
      stats.appendChild(card);
    }

    appendStatCard(summary.devices_total || 0, 'Devices');
    appendStatCard(summary.active_sessions || 0, 'Active SSH', 'color-mix(in srgb, var(--ok) 50%, var(--line))', 'var(--ok)');
    appendStatCard(summary.online || 0, 'Online', 'color-mix(in srgb, var(--ok) 45%, var(--line))', 'var(--ok)');
    appendStatCard(summary.offline || 0, 'Offline', (summary.offline || 0) ? 'color-mix(in srgb, var(--bad) 50%, var(--line))' : null, (summary.offline || 0) ? 'var(--bad)' : null);
    appendStatCard(summary.stale || 0, 'Stale', (summary.stale || 0) ? 'color-mix(in srgb, var(--warn) 50%, var(--line))' : null, (summary.stale || 0) ? 'var(--warn)' : null);
    appendStatCard(summary.errors || 0, 'Errors', (summary.errors || 0) ? 'color-mix(in srgb, var(--bad) 50%, var(--line))' : null, (summary.errors || 0) ? 'var(--bad)' : null);
  },
  formatFreshness: function(seconds, stale) {
    if (seconds == null || !Number.isFinite(Number(seconds))) return 'never';
    var s = Math.max(0, Number(seconds));
    var txt = s < 60 ? (Math.floor(s) + 's ago') : (Math.floor(s / 60) + 'm ago');
    return stale ? (txt + ' (stale)') : txt;
  },
  renderDeviceStatuses: function(items) {
    var self = this;
    var grid = App.el('dashDevStatusGrid');
    if (!grid) return;
    App.clearNode(grid);
    if (!items.length) {
      grid.appendChild(App.createEl('div', { className: 'muted', text: 'No devices yet. Add devices on the Devices page.' }));
      return;
    }
    for (var i = 0; i < items.length; i++) {
      (function(d) {
        d = self.mergeWithCachedStatus(d);
        var isActive = (d.session_state || d.status) === 'active';
        var hasError = !!d.last_error;
        var isStale = !!d.stale;
        var isSelected = App.state.selectedDevice && App.state.selectedDevice.id === d.id;
        var cls = (isActive ? 'active ' : '') + (hasError ? 'error ' : '') + (isStale ? 'stale ' : '') + (isSelected ? 'selected' : '');
        var card = document.createElement('div');
        card.className = 'dev-status-card ' + cls.trim();
        card.dataset.deviceId = String(d.id);
        var statusTxt = isActive ? 'Session active' : 'Session reconnect';
        var idleTxt = isActive && d.idle_seconds != null ? (d.idle_seconds + 's') : '-';
        var uptimeTxt = d.uptime || '-';
        var rosTxt = d.ros_version || '-';
        var healthTxt = d.health_state || 'unknown';
        var checkedTxt = self.formatFreshness(d.freshness_seconds, d.stale);
        var main = document.createElement('div');
        main.className = 'dev-status-main';
        var head = document.createElement('div');
        head.className = 'dev-status-head';
        var title = document.createElement('div');
        title.className = 'dev-status-title';
        title.textContent = d.name;
        var chip = document.createElement('span');
        chip.className = 'dev-status-chip ' + (isActive ? 'active' : (hasError ? 'error' : 'idle'));
        chip.dataset.role = 'status-chip';
        chip.textContent = statusTxt;
        var connectBtn = document.createElement('button');
        connectBtn.className = 'secondary';
        connectBtn.textContent = isActive ? 'Retest' : 'Connect';
        connectBtn.dataset.role = 'connect-btn';
        connectBtn.type = 'button';
        connectBtn.onclick = async function(e) {
          e.stopPropagation();
          connectBtn.disabled = true;
          disconnectBtn.disabled = true;
          try {
            var dev = App.state.devices.find(function(x) { return x.id === d.id; }) || d;
            await self.connectDevice(dev);
          } finally {
            connectBtn.disabled = false;
            disconnectBtn.disabled = false;
          }
        };
        var disconnectBtn = document.createElement('button');
        disconnectBtn.className = 'secondary';
        disconnectBtn.textContent = 'Disconnect';
        disconnectBtn.dataset.role = 'disconnect-btn';
        disconnectBtn.type = 'button';
        disconnectBtn.disabled = !App.can('operator');
        disconnectBtn.onclick = async function(e) {
          e.stopPropagation();
          connectBtn.disabled = true;
          disconnectBtn.disabled = true;
          try {
            var dev = App.state.devices.find(function(x) { return x.id === d.id; }) || d;
            await self.disconnectDevice(dev);
          } finally {
            connectBtn.disabled = false;
            disconnectBtn.disabled = !App.can('operator');
          }
        };
        head.appendChild(title);
        head.appendChild(chip);
        main.appendChild(head);
        var meta = document.createElement('div');
        meta.className = 'dev-status-meta';
        function appendMetaRow(label, value, role) {
          var row = document.createElement('div');
          row.appendChild(document.createTextNode(label));
          var strong = document.createElement('strong');
          strong.dataset.role = role;
          strong.textContent = value;
          row.appendChild(strong);
          meta.appendChild(row);
        }
        appendMetaRow('Host', d.host + ':' + d.port, 'host');
        appendMetaRow('Health', healthTxt, 'health-state');
        appendMetaRow('Checked', checkedTxt, 'checked-at');
        appendMetaRow('Uptime', uptimeTxt, 'uptime');
        appendMetaRow('RouterOS', rosTxt, 'ros-version');
        appendMetaRow('Idle', idleTxt, 'idle');
        appendMetaRow('Queue', d.queue_depth != null ? d.queue_depth : '-', 'queue-depth');
        appendMetaRow('Reconnects', d.reconnect_count != null ? d.reconnect_count : '-', 'reconnects');
        main.appendChild(meta);
        var err = document.createElement('div');
        err.className = 'dev-status-error';
        err.dataset.role = 'status-error';
        if (d.last_error) {
          err.title = d.last_error;
          err.textContent = 'Error: ' + d.last_error;
        } else {
          err.textContent = '';
          err.style.display = 'none';
        }
        main.appendChild(err);
        var actions = document.createElement('div');
        actions.className = 'dev-status-actions';
        actions.appendChild(connectBtn);
        actions.appendChild(disconnectBtn);
        main.appendChild(actions);
        card.appendChild(main);
        card.onclick = function(e) {
          if (connectBtn.contains(e.target) || disconnectBtn.contains(e.target)) return;
          var dev = App.state.devices.find(function(x) { return x.id === d.id; });
          if (dev) self.setSelectedDashboardDevice(dev);
        };
        grid.appendChild(card);
      })(items[i]);
    }
  },
  applyStatusToExistingCard: function(d) {
    d = this.mergeWithCachedStatus(d);
    var card = document.querySelector('.dev-status-card[data-device-id="' + d.id + '"]');
    if (!card) return;

    var isActive = (d.session_state || d.status) === 'active';
    var hasError = !!d.last_error;
    var isStale = !!d.stale;
    var isSelected = App.state.selectedDevice && App.state.selectedDevice.id === d.id;
    card.classList.toggle('active', !!isActive);
    card.classList.toggle('error', !!hasError);
    card.classList.toggle('stale', !!isStale);
    card.classList.toggle('selected', !!isSelected);

    var chip = card.querySelector('[data-role="status-chip"]');
    if (chip) {
      chip.classList.remove('active', 'error', 'idle');
      chip.classList.add(isActive ? 'active' : (hasError ? 'error' : 'idle'));
      chip.textContent = isActive ? 'Session active' : 'Session reconnect';
    }

    var idle = card.querySelector('[data-role="idle"]');
    if (idle) idle.textContent = (isActive && d.idle_seconds != null) ? (d.idle_seconds + 's') : '-';

    var uptime = card.querySelector('[data-role="uptime"]');
    if (uptime) {
      if (d.uptime) uptime.textContent = d.uptime;
      else if (!uptime.textContent || uptime.textContent === '-') uptime.textContent = '-';
    }

    var ros = card.querySelector('[data-role="ros-version"]');
    if (ros) {
      if (d.ros_version) ros.textContent = d.ros_version;
      else if (!ros.textContent || ros.textContent === '-') ros.textContent = '-';
    }

    var reconnects = card.querySelector('[data-role="reconnects"]');
    if (reconnects) reconnects.textContent = d.reconnect_count != null ? d.reconnect_count : '-';

    var health = card.querySelector('[data-role="health-state"]');
    if (health) health.textContent = d.health_state || 'unknown';

    var checked = card.querySelector('[data-role="checked-at"]');
    if (checked) checked.textContent = this.formatFreshness(d.freshness_seconds, d.stale);

    var queue = card.querySelector('[data-role="queue-depth"]');
    if (queue) queue.textContent = d.queue_depth != null ? d.queue_depth : '-';

    var err = card.querySelector('[data-role="status-error"]');
    if (err) {
      if (d.last_error) {
        err.style.display = '';
        err.title = d.last_error;
        err.textContent = 'Error: ' + d.last_error;
      } else {
        err.style.display = 'none';
        err.textContent = '';
        err.title = '';
      }
    }

    var connectBtn = card.querySelector('[data-role="connect-btn"]');
    if (connectBtn) connectBtn.textContent = isActive ? 'Retest' : 'Connect';
  },
});
