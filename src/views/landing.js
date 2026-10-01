import { escapeHtml as esc } from '../core/util.js';
import { authPage, mark } from './layout.js';

/** 首页:未登录时的服务介绍与入口 */
export function landingPage({ theme, siteName, issuer, logged, msg }) {
  return authPage({
    theme, siteName, title: `${siteName} · OAuth2 / OIDC 统一认证`,
    content: `
      ${msg ? `<div class="banner ok">${esc(msg)}</div>` : ''}
      <h3 style="margin-top:0">这一站,管好你所有系统的登录。</h3>
      <p class="small" style="margin-top:0">${esc(siteName)} 是一个 OAuth 2.0 / OpenID Connect 认证服务:业务系统统一跳转到这里登录,拿回令牌后访问各自的接口,密码只存在这一处。</p>
      <div class="actions">
        ${logged
          ? '<a class="btn btn-primary" href="/apps">应用门户</a><a class="btn" href="/admin">管理控制台</a>'
          : '<a class="btn btn-primary" href="/login">登录</a><a class="btn" href="/logout">退出登录</a>'}
      </div>
      <h3>接入方</h3>
      <div class="kv"><b>Issuer</b><span>${esc(issuer)}</span></div>
      <div class="kv"><b>发现文档</b><span><a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a></span></div>
      <div class="kv"><b>JWKS</b><span><a href="/jwks.json">/jwks.json</a></span></div>
      <p class="muted small">支持授权码 + PKCE、刷新令牌、客户端凭证模式,令牌为 RS256 签名的 JWT。</p>`,
  });
}
