(function() {
  var saved = localStorage.getItem('mimTheme');
  if (saved === 'dark') document.body.classList.add('dark');

  (function() {
    var bd = App.el('pwModalBackdrop');
    var mc = App.el('pwModalCard');
    var st = App.el('pwModalStatus');
    function closePw() { bd.classList.add('hidden'); mc.classList.add('hidden'); }
    App.el('pwModalCancel').onclick = closePw;
    bd.onclick = closePw;
    App.el('pwModalSave').onclick = async function() {
      var pw = App.el('pwModalPass').value;
      var conf = App.el('pwModalConfirm').value;
      if (!pw) { st.textContent = 'Enter new password'; st.style.color = 'var(--bad)'; return; }
      if (pw !== conf) { st.textContent = 'Passwords do not match'; st.style.color = 'var(--bad)'; return; }
      st.textContent = 'Saving...'; st.style.color = 'var(--muted)';
      try {
        await App.api('/api/users/' + mc._targetId + '/password', {
          method: 'PUT', body: JSON.stringify({ new_password: pw }),
        });
        st.textContent = 'Password changed successfully'; st.style.color = 'var(--ok)';
        setTimeout(closePw, 1200);
      } catch(err) { st.textContent = err.message; st.style.color = 'var(--bad)'; }
    };
  })();

  App.el('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    var authStatus = App.el('authStatus');
    try {
      var fd = new FormData(e.target);
      var out = await App.api('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username: String(fd.get('username') || '').trim(), password: String(fd.get('password') || '') }),
      });
      App.state.token = out.token;
      localStorage.setItem('mimToken', out.token);
      authStatus.textContent = 'Signed in';
      authStatus.style.color = 'var(--ok)';
      await App.bootstrap();
    } catch (err) {
      authStatus.textContent = err.message;
      authStatus.style.color = 'var(--bad)';
    }
  });

  (async function() {
    if (!App.state.token) return;
    try { await App.bootstrap(); }
    catch(e) { App.logout(); }
  })();

  setInterval(function() {
    if (!App.state.selectedDevice || !App.state.token) return;
    var p = App.pages.find(function(p) { return p.id === 'interfaces'; });
    if (p && p.loadSshStatus) p.loadSshStatus();
  }, 10000);
})();
