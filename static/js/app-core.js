const App = (() => {
  const state = {
    token: localStorage.getItem('mimToken') || '',
    currentUser: null,
    selectedDevice: null,
    devices: [],
    pendingBroadcast: null,
    editingInterfaceName: '',
    globalSelector: null,
  };

  const roleLevel = { viewer: 1, operator: 2, admin: 3 };
  const pages = [];

  function can(role) {
    if (!state.currentUser) return false;
    return roleLevel[state.currentUser.role] >= roleLevel[role];
  }

  function el(id) { return document.getElementById(id); }

  function status(msg, isError) {
    if (!msg) return;

    // Keep a small inline status for compatibility, but rely on stacked toasts for UX.
    const s = el('globalStatus');
    if (s) { s.textContent = msg; s.style.color = isError ? 'var(--bad)' : 'var(--muted)'; }

    const stack = el('toastStack');
    if (!stack) return;
    const toast = document.createElement('div');
    toast.className = 'toast' + (isError ? ' error' : '');
    toast.textContent = msg;
    stack.prepend(toast);
    while (stack.children.length > 5) {
      stack.removeChild(stack.lastChild);
    }
    setTimeout(function() {
      toast.classList.add('leaving');
      setTimeout(function() {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 220);
    }, 4000);
  }

  async function api(url, options) {
    options = options || {};
    const headers = { 'Content-Type': 'application/json' };
    if (options.headers) Object.assign(headers, options.headers);
    if (state.token) headers.Authorization = 'Bearer ' + state.token;
    const resp = await fetch(url, Object.assign({}, options, { headers: headers }));
    if (resp.status === 401) { logout(); throw new Error('Session expired'); }
    if (!resp.ok) {
      const ct = resp.headers.get('content-type') || '';
      if (ct.indexOf('application/json') !== -1) {
        const data = await resp.json();
        const det = data.detail;
        throw new Error(typeof det === 'string' ? det : Array.isArray(det) ? det.map(function(e){return e.msg || JSON.stringify(e);}).join('; ') : JSON.stringify(data));
      }
      throw new Error((await resp.text()) || 'API error');
    }
    const ct = resp.headers.get('content-type') || '';
    return ct.indexOf('application/json') !== -1 ? resp.json() : {};
  }

  function logout() {
    state.token = '';
    state.currentUser = null;
    state.selectedDevice = null;
    state.devices = [];
    localStorage.removeItem('mimToken');
    state.globalSelector = null;
    el('app').style.display = 'none';
    el('authGate').style.display = 'grid';
  }

  function selectDevice(device) {
    state.selectedDevice = device;
    document.querySelectorAll('.device-select-dropdown').forEach(function(sel) { sel.value = device ? device.id : ''; });
    if (state.globalSelector && state.globalSelector.refresh) state.globalSelector.refresh();
    for (var i = 0; i < pages.length; i++) {
      if (!pages[i].onDeviceChanged) continue;
      var section = el('page-' + pages[i].id);
      // Avoid side effects (SSH/API calls) from inactive pages on global device switch.
      if (section && section.classList.contains('active')) pages[i].onDeviceChanged(device);
    }
  }

  function buildDeviceSelector(container) {
    container.innerHTML = '<span class="muted">Device:</span><select class="device-select-dropdown"><option value="">-- select --</option></select><strong class="device-select-label" style="white-space:nowrap"></strong>';
    var sel = container.querySelector('.device-select-dropdown');
    var label = container.querySelector('.device-select-label');

    function refresh() {
      var val = sel.value;
      sel.innerHTML = '<option value="">-- select --</option>';
      for (var i = 0; i < state.devices.length; i++) {
        var d = state.devices[i];
        var opt = document.createElement('option');
        opt.value = d.id;
        opt.textContent = d.name + ' (' + d.host + ')';
        sel.appendChild(opt);
      }
      if (state.selectedDevice) { sel.value = state.selectedDevice.id; label.textContent = state.selectedDevice.name; }
      else { label.textContent = ''; }
    }
    sel.onchange = function() {
      var id = Number(sel.value);
      var dev = state.devices.find(function(d) { return d.id === id; }) || null;
      selectDevice(dev);
    };
    refresh();
    return { refresh: refresh };
  }

  function addPage(id, label, icon, opts) {
    opts = opts || {};
    var page = Object.assign({
      id: id, label: label, icon: icon,
      minRole: 'viewer',
      init: function(){},
      onEnter: function(){},
      onDeviceChanged: null,
    }, opts, { id: id, label: label, icon: icon });
    pages.push(page);
    return page;
  }

  function navigate(pageId) {
    for (var i = 0; i < pages.length; i++) {
      var section = el('page-' + pages[i].id);
      if (section) section.classList.toggle('active', pages[i].id === pageId);
    }
    document.querySelectorAll('.nav-btn').forEach(function(btn) {
      btn.classList.toggle('active', btn.dataset.page === pageId);
    });
    var page = pages.find(function(p) { return p.id === pageId; });
    if (page && page.onEnter) page.onEnter();
  }

  function buildNavbar() {
    var nav = el('navbar');
    nav.innerHTML = '';
    var brand = document.createElement('span');
    brand.className = 'navbar-brand'; brand.textContent = 'MikroTik';
    nav.appendChild(brand);
    var sep = document.createElement('div');
    sep.className = 'navbar-sep';
    nav.appendChild(sep);
    var items = document.createElement('div');
    items.className = 'nav-items';
    for (var i = 0; i < pages.length; i++) {
      var p = pages[i];
      if (!can(p.minRole)) continue;
      var btn = document.createElement('button');
      btn.className = 'nav-btn'; btn.dataset.page = p.id;
      btn.innerHTML = '<span class="nav-icon">' + p.icon + '</span> ' + p.label;
      btn.onclick = (function(pid) { return function() { navigate(pid); }; })(p.id);
      items.appendChild(btn);
    }
    nav.appendChild(items);
    var right = document.createElement('div');
    right.className = 'nav-right';

    var selectorHost = document.createElement('div');
    selectorHost.className = 'nav-device-host';
    right.appendChild(selectorHost);

    state.globalSelector = buildDeviceSelector(selectorHost);

    var userLabel = document.createElement('span');
    userLabel.className = 'nav-user';
    userLabel.textContent = state.currentUser ? state.currentUser.username + ' • ' + state.currentUser.role : '';
    right.appendChild(userLabel);
    var pwBtn = document.createElement('button');
    pwBtn.className = 'nav-small-btn'; pwBtn.title = 'Change Password'; pwBtn.textContent = '🔑';
    pwBtn.onclick = function() { if (state.currentUser) App.openPwModal(state.currentUser.id, state.currentUser.username); };
    right.appendChild(pwBtn);
    var themeBtn = document.createElement('button');
    themeBtn.className = 'nav-small-btn';
    themeBtn.textContent = document.body.classList.contains('dark') ? '☀️' : '🌙';
    themeBtn.title = document.body.classList.contains('dark') ? 'Switch to light theme' : 'Switch to dark theme';
    themeBtn.onclick = function() {
      var dark = document.body.classList.toggle('dark');
      localStorage.setItem('mimTheme', dark ? 'dark' : 'light');
      themeBtn.textContent = dark ? '☀️' : '🌙';
      themeBtn.title = dark ? 'Switch to light theme' : 'Switch to dark theme';
    };
    right.appendChild(themeBtn);
    var logoutBtn = document.createElement('button');
    logoutBtn.className = 'nav-small-btn'; logoutBtn.textContent = 'Logout';
    logoutBtn.onclick = logout;
    right.appendChild(logoutBtn);
    nav.appendChild(right);
  }

  async function loadDevices() {
    try {
      state.devices = await api('/api/devices');
      document.querySelectorAll('.device-select-dropdown').forEach(function(sel) {
        var val = sel.value;
        sel.innerHTML = '<option value="">-- select --</option>';
        for (var i = 0; i < state.devices.length; i++) {
          var d = state.devices[i];
          var opt = document.createElement('option');
          opt.value = d.id; opt.textContent = d.name + ' (' + d.host + ')';
          sel.appendChild(opt);
        }
        sel.value = val;
      });

      if (state.selectedDevice) {
        var stillExists = state.devices.find(function(d) { return d.id === state.selectedDevice.id; });
        state.selectedDevice = stillExists || null;
      }
      if (state.globalSelector && state.globalSelector.refresh) state.globalSelector.refresh();
      return state.devices;
    } catch (e) { status(e.message, true); return []; }
  }

  async function bootstrap() {
    var me = await api('/api/auth/me');
    state.currentUser = me;
    el('authGate').style.display = 'none';
    el('app').style.display = 'block';
    buildNavbar();
    for (var i = 0; i < pages.length; i++) pages[i].init();
    await loadDevices();
    navigate('dashboard');
  }

  return {
    state: state, can: can, el: el, status: status, api: api, logout: logout,
    selectDevice: selectDevice, buildDeviceSelector: buildDeviceSelector,
    addPage: addPage, navigate: navigate, buildNavbar: buildNavbar,
    loadDevices: loadDevices, bootstrap: bootstrap, pages: pages,
    openPwModal: function(userId, username) {
      var bd = el('pwModalBackdrop'); var mc = el('pwModalCard');
      if (!bd || !mc) return;
      el('pwModalFor').textContent = 'User: ' + username;
      el('pwModalPass').value = ''; el('pwModalConfirm').value = '';
      el('pwModalStatus').textContent = '';
      mc._targetId = userId;
      bd.classList.remove('hidden'); mc.classList.remove('hidden');
    },
  };
})();
