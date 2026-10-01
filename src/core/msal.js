import crypto from 'node:crypto';
import { nowSec } from './crypto.js';

/**
 * Microsoft Entra ID(OAuth2 / OIDC)联邦登录的最小客户端实现:零依赖,全局 fetch。
 * 授权端点拼接、授权码换取令牌、id_token 的 JWKS 验签与 aud/exp/iss 校验。
 */

const FETCH_TIMEOUT_MS = 10000;      // 全局 fetch 统一 10s 超时
const JWKS_TTL_MS = 60 * 60 * 1000;  // JWKS 内存缓存 1 小时

const trimSlash = (s) => String(s || '').replace(/\/+$/, '');

/* ---------------- 授权端点 ---------------- */

/** 拼授权端点 URL(scope 用 %20 编码,参数顺序与规格一致) */
export function buildAuthUrl({ tenant, clientId, redirectUri, state, codeChallenge, authority = 'https://login.microsoftonline.com' }) {
  const q = [
    ['response_type', 'code'],
    ['scope', 'openid profile email'],
    ['client_id', clientId],
    ['redirect_uri', redirectUri],
    ['state', state],
    ['code_challenge', codeChallenge],
    ['code_challenge_method', 'S256'],
    ['prompt', 'select_account'],
  ].map(([k, v]) => `${k}=${encodeURIComponent(String(v))}`).join('&');
  return `${trimSlash(authority)}/${tenant}/oauth2/v2.0/authorize?${q}`;
}

/* ---------------- 令牌端点 ---------------- */

/** 授权码 + code_verifier 换取令牌;HTTP 非 2xx 或响应带 error 时抛错 */
export async function exchangeCode({ tenant, clientId, clientSecret, redirectUri, code, codeVerifier, authority = 'https://login.microsoftonline.com' }) {
  let res;
  try {
    res = await fetch(`${trimSlash(authority)}/${tenant}/oauth2/v2.0/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        code,
        code_verifier: codeVerifier,
      }).toString(),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (err) {
    throw new Error(`无法连接 Microsoft 令牌端点:${err.message || err}`);
  }
  let data = {};
  try { data = await res.json(); } catch { /* 非 JSON 响应按空对象处理 */ }
  if (!res.ok || data.error) {
    throw new Error(data.error_description || data.error || `令牌端点返回 HTTP ${res.status}`);
  }
  return data;
}

/* ---------------- id_token 验签 ---------------- */

let jwksCache = null; // { authority, keys, fetchedAt }

/** 拉取 {authority}/common/discovery/v2.0/keys,内存缓存 1 小时 */
async function getJwks(authority) {
  const base = trimSlash(authority);
  if (jwksCache && jwksCache.authority === base && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  let res;
  try {
    res = await fetch(`${base}/common/discovery/v2.0/keys`, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (err) {
    throw new Error(`无法获取 JWKS:${err.message || err}`);
  }
  if (!res.ok) throw new Error(`获取 JWKS 失败(HTTP ${res.status})`);
  const data = await res.json();
  if (!Array.isArray(data.keys) || !data.keys.length) throw new Error('JWKS 中没有可用密钥');
  jwksCache = { authority: base, keys: data.keys, fetchedAt: Date.now() };
  return data.keys;
}

/**
 * 验证 Microsoft 签发的 id_token:按 kid 找 JWK → RS256 验签 → aud/exp/iss 校验。
 * 通过返回 { sub, email, preferred_username, name };失败抛错(消息直接展示给用户)。
 */
export async function verifyIdToken(idToken, { clientId, tenant, authority = 'https://login.microsoftonline.com' }) {
  const base = trimSlash(authority);
  const [h, p, sig] = String(idToken).split('.');
  if (!h || !p || !sig) throw new Error('id_token 格式不正确');
  let header;
  try { header = JSON.parse(Buffer.from(h, 'base64url').toString()); } catch { throw new Error('id_token 头部无法解析'); }
  if (header.alg !== 'RS256') throw new Error('id_token 签名算法不是 RS256');
  const keys = await getJwks(base);
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('id_token 的 kid 在 JWKS 中不存在');
  const keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = crypto.createVerify('RSA-SHA256').update(`${h}.${p}`).verify(keyObject, sig, 'base64url');
  if (!ok) throw new Error('id_token 验签失败');
  let payload;
  try { payload = JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { throw new Error('id_token 载荷无法解析'); }
  if (payload.aud !== clientId) throw new Error('id_token 的 aud 与 client_id 不符');
  if (payload.exp !== undefined && payload.exp <= nowSec()) throw new Error('id_token 已过期');
  const expectedIss = `${base}/${tenant}/v2.0`;
  if (payload.iss !== expectedIss) throw new Error(`id_token 的 iss 不符(期望 ${expectedIss})`);
  return {
    sub: payload.sub,
    email: payload.email || '',
    preferred_username: payload.preferred_username || '',
    name: payload.name || '',
  };
}
