/**
 * /assets/webauthn.js 的源文本(全项目唯一的页面 JS 资产):
 * 零依赖,仅同源 fetch + navigator.credentials。经元素 id 绑定事件,不用内联 onclick:
 * - 登录页:#passkey-login-btn(按钮)、#passkey-status(状态行)
 * - 账号页:#passkey-register-btn(按钮)、#passkey-name(备注输入)、#passkey-status(状态行)
 * 凭据删除为普通表单提交,不依赖本脚本。浏览器不支持 WebAuthn 时隐藏按钮并提示。
 */
export const WEBAUTHN_JS = `/* Sakura-Auth-Server Passkey(WebAuthn)—— 零依赖,同源调用 */
(function () {
  'use strict';
  var AJAX = { 'X-Requested-With': 'JSON' };

  function status(msg, bad) {
    var el = document.getElementById('passkey-status');
    if (el) {
      el.textContent = msg || '';
      el.style.color = bad ? 'var(--danger)' : '';
    }
  }
  function b64u(buf) {
    var u = new Uint8Array(buf), s = '';
    for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  }
  function unb64u(s) {
    var b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/'));
    var u = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u.buffer;
  }
  function post(url, body) {
    return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  }
  function errMsg(data, res, fallback) {
    if (data && data.error === 'no_credentials') return '尚未注册 Passkey,请先用密码登录并在账号设置中注册';
    if (data && data.error === 'too_many') return 'Passkey 数量已达上限(每个账号最多 8 个)';
    if (data && data.error === 'credential_cloned') return '检测到凭据数据异常,已拒绝本次登录';
    if (data && data.message) return data.message;
    return fallback;
  }
  function failText(res, data, fallback) {
    return function (e) { throw new Error(e && e.name === 'NotAllowedError' ? '已取消或超时' : errMsg(data, res, fallback)); };
  }

  if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
    ['passkey-login-btn', 'passkey-register-btn'].forEach(function (id) {
      var b = document.getElementById(id);
      if (b) b.style.display = 'none';
    });
    status('此浏览器不支持 Passkey,请使用密码登录。', true);
    return;
  }

  /* 注册:仅账号设置页(存在 #passkey-register-btn 时绑定) */
  var regBtn = document.getElementById('passkey-register-btn');
  if (regBtn) regBtn.addEventListener('click', function () {
    status('正在等待认证器创建 Passkey…');
    fetch('/webauthn/register/options', { headers: AJAX })
      .then(function (res) {
        if (!res.ok) throw new Error('获取注册参数失败,请重新登录后再试');
        return res.json();
      })
      .then(function (opts) {
        var pk = opts.publicKey;
        pk.challenge = unb64u(pk.challenge);
        pk.user.id = unb64u(pk.user.id);
        (pk.excludeCredentials || []).forEach(function (c) { c.id = unb64u(c.id); });
        return navigator.credentials.create({ publicKey: pk });
      })
      .then(function (cred) {
        var nameInput = document.getElementById('passkey-name');
        var name = (nameInput && nameInput.value || '').trim() || 'Passkey';
        return post('/webauthn/register/verify', {
          name: name,
          response: {
            clientDataJSON: b64u(cred.response.clientDataJSON),
            attestationObject: b64u(cred.response.attestationObject),
            transports: cred.response.getTransports ? cred.response.getTransports() : []
          }
        }).then(function (res) {
          return res.json().catch(function () { return {}; }).then(function (data) {
            if (!res.ok) return failText(res, data, '注册失败,请重试')(null);
            status('Passkey 注册成功,正在刷新…');
            location.reload();
            throw new Error('reload');
          });
        });
      })
      .catch(function (e) { if (e.message !== 'reload') status(e.message || '注册失败', true); });
  });

  /* 登录:仅登录页(存在 #passkey-login-btn 时绑定) */
  var loginBtn = document.getElementById('passkey-login-btn');
  if (loginBtn) loginBtn.addEventListener('click', function () {
    status('正在等待 Passkey 验证…');
    fetch('/webauthn/login/options', { headers: AJAX })
      .then(function (res) {
        if (!res.ok) throw new Error('获取登录参数失败');
        return res.json();
      })
      .then(function (o) {
        var pk = {
          challenge: unb64u(o.challenge),
          rpId: o.rpId,
          timeout: o.timeout,
          userVerification: o.userVerification
        };
        if (o.allowCredentials && o.allowCredentials.length) {
          pk.allowCredentials = o.allowCredentials.map(function (c) {
            return { type: c.type, id: unb64u(c.id) };
          });
        }
        return navigator.credentials.get({ publicKey: pk }).then(function (cred) {
          return post('/webauthn/login/verify', {
            challengeId: o.challengeId,
            response: {
              id: cred.id,
              rawId: b64u(cred.rawId),
              type: cred.type,
              response: {
                clientDataJSON: b64u(cred.response.clientDataJSON),
                authenticatorData: b64u(cred.response.authenticatorData),
                signature: b64u(cred.response.signature),
                userHandle: cred.response.userHandle ? b64u(cred.response.userHandle) : ''
              }
            }
          }).then(function (res) {
            return res.json().catch(function () { return {}; }).then(function (data) {
              if (!res.ok) return failText(res, data, 'Passkey 验证未通过')(null);
              location.href = '/apps';
              throw new Error('nav');
            });
          });
        });
      })
      .catch(function (e) { if (e.message !== 'nav') status(e.message || 'Passkey 登录失败', true); });
  });
})();
`;
