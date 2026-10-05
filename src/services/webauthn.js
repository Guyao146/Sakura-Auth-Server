/**
 * WebAuthn/Passkey 服务:注册/登录的 options 与 verify、凭据删除、JS 资产下发。
 * 挑战暂存于进程内 Map(与登录限流同一模式):注册按 user_id 键,登录按 challengeId 键,
 * 容量 500、TTL 5 分钟,插入时惰性清理过期项;挑战取出即作废(一次性)。
 */
import * as users from '../models/users.js';
import * as creds from '../models/webauthn.js';
import { randomToken } from '../core/crypto.js';
import { getRuntime } from '../core/runtime.js';
import { sendJson, redirect } from '../core/http.js';
import { logger } from '../core/logger.js';
import { record } from './audit.js';
import { startSession, sessionMeta } from './auth/login.js';
import { parseAttestation, verifyAssertion } from '../core/webauthn.js';
import { WEBAUTHN_JS } from './webauthn-js.js';

const NO_STORE = { 'Cache-Control': 'no-store' };
const CHALLENGE_CAP = 500;
const CHALLENGE_TTL = 5 * 60 * 1000;
const challenges = new Map(); // 'reg:<userId>' | 'login:<challengeId>' → { challenge, expires }

/** JSON API 深度防御(与 api.js 同约定):cookie 会话的写操作要求显式 X-Requested-With 头 */
const requiresAjaxGuard = (ctx) => ctx.req.headers['x-requested-with'] !== 'JSON';

function pruneChallenges() {
  const now = Date.now();
  for (const [k, v] of challenges) {
    if (v.expires <= now) challenges.delete(k);
  }
}

function putChallenge(key, challenge) {
  pruneChallenges();
  if (challenges.size >= CHALLENGE_CAP) challenges.delete(challenges.keys().next().value);
  challenges.set(key, { challenge, expires: Date.now() + CHALLENGE_TTL });
}

/** 取出挑战(一次性:取出即删除,防重放) */
function takeChallenge(key) {
  const v = challenges.get(key);
  if (!v) return null;
  challenges.delete(key);
  return v.expires > Date.now() ? v.challenge : null;
}

const rpId = () => new URL(getRuntime().issuer).hostname;

/** GET /assets/webauthn.js —— 同源 JS 资产(CSP default-src 'self' 天然放行,匿名可访问) */
export function serveJs(ctx) {
  ctx.res.setHeader('X-Content-Type-Options', 'nosniff');
  ctx.res.setHeader('Cache-Control', 'public, max-age=300');
  ctx.res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8' });
  ctx.res.end(WEBAUTHN_JS);
}

/** GET /webauthn/register/options —— 注册参数(需登录;challenge 按 user_id 暂存) */
export function registerOptions(ctx) {
  if (!ctx.user) return sendJson(ctx.res, 401, { error: 'unauthenticated' }, NO_STORE);
  const rt = getRuntime();
  const challenge = randomToken(32);
  putChallenge(`reg:${ctx.user.id}`, challenge);
  sendJson(ctx.res, 200, {
    publicKey: {
      rp: { name: rt.siteName, id: rpId() },
      user: {
        id: Buffer.from(ctx.user.id).toString('base64url'),
        name: ctx.user.username,
        displayName: ctx.user.name || ctx.user.username,
      },
      challenge,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      // 已注册凭据作为 exclude,提示认证器避免重复注册同名凭据
      excludeCredentials: creds.listForUser(ctx.user.id).map((c) => ({ type: 'public-key', id: c.id })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      timeout: 60000,
    },
  }, NO_STORE);
}

/** POST /webauthn/register/verify —— 校验 attestation 并入库(需登录 + Ajax 头) */
export function registerVerify(ctx) {
  if (!ctx.user) return sendJson(ctx.res, 401, { error: 'unauthenticated' }, NO_STORE);
  if (requiresAjaxGuard(ctx)) return sendJson(ctx.res, 403, { error: 'ajax_header_required' }, NO_STORE);
  const rt = getRuntime();
  const resp = ctx.body?.response || {};
  const clientDataJSON = typeof resp.clientDataJSON === 'string' ? resp.clientDataJSON : '';
  const attestationObject = typeof resp.attestationObject === 'string' ? resp.attestationObject : '';
  if (!clientDataJSON || !attestationObject) {
    return sendJson(ctx.res, 400, { error: 'bad_request' }, NO_STORE);
  }
  const challenge = takeChallenge(`reg:${ctx.user.id}`);
  if (!challenge) return sendJson(ctx.res, 400, { error: 'challenge_expired' }, NO_STORE);
  let att;
  try {
    att = parseAttestation({
      attestationObject, clientDataJSON,
      expectedChallenge: challenge, expectedOrigin: new URL(rt.issuer).origin, rpId: rpId(),
    });
  } catch (e) {
    logger.warn('Passkey 注册校验失败', { code: e.code, err: e.message });
    return sendJson(ctx.res, 400, { error: e.code || 'attestation_invalid' }, NO_STORE);
  }
  const credIdB64 = att.credentialId.toString('base64url');
  if (creds.byId(credIdB64)) return sendJson(ctx.res, 400, { error: 'duplicate' }, NO_STORE);
  if (creds.countForUser(ctx.user.id) >= creds.MAX_PER_USER) {
    return sendJson(ctx.res, 400, { error: 'too_many' }, NO_STORE);
  }
  const name = typeof ctx.body?.name === 'string' && ctx.body.name.trim()
    ? ctx.body.name.trim().slice(0, 40) : 'Passkey';
  creds.create({
    id: credIdB64,
    userId: ctx.user.id,
    name,
    publicKey: att.cosePublicKey.toString('base64url'),
    counter: att.signCount,
    transports: Array.isArray(resp.transports) ? resp.transports.map(String).join(',') : '',
  });
  record(ctx, 'account.passkey_registered', name);
  logger.info('Passkey 注册成功', { user: ctx.user.username, name });
  return sendJson(ctx.res, 200, { ok: true, name }, NO_STORE);
}

/** GET /webauthn/login/options —— 登录参数(匿名;可选 username 缩小 allowCredentials) */
export function loginOptions(ctx) {
  const challengeId = randomToken(18);
  const challenge = randomToken(32);
  putChallenge(`login:${challengeId}`, challenge);
  let allow = [];
  const username = ctx.query.get('username');
  if (username) {
    const u = users.byUsername(String(username));
    if (u) allow = creds.listForUser(u.id).map((c) => ({ type: 'public-key', id: c.id }));
  }
  sendJson(ctx.res, 200, {
    challengeId,
    challenge,
    rpId: rpId(),
    userVerification: 'required',
    timeout: 60000,
    allowCredentials: allow,
  }, NO_STORE);
}

/** POST /webauthn/login/verify —— 校验 assertion 并建立会话(匿名 + Ajax 头) */
export function loginVerify(ctx) {
  if (requiresAjaxGuard(ctx)) return sendJson(ctx.res, 403, { error: 'ajax_header_required' }, NO_STORE);
  const rt = getRuntime();
  // 浏览器 PublicKeyCredential 形状:{ id, rawId, type, response:{ clientDataJSON, authenticatorData, signature } };
  // 兼容扁平形状(response 内直接携带 assertion 字段)
  const outer = ctx.body?.response || {};
  const inner = outer.response || {};
  const pick = (a, b) => (typeof a === 'string' && a ? a : (typeof b === 'string' ? b : ''));
  const clientDataJSON = pick(inner.clientDataJSON, outer.clientDataJSON);
  const authenticatorData = pick(inner.authenticatorData, outer.authenticatorData);
  const signature = pick(inner.signature, outer.signature);
  const challengeId = typeof ctx.body?.challengeId === 'string' ? ctx.body.challengeId : '';
  if (!challengeId || !clientDataJSON || !authenticatorData || !signature) {
    return sendJson(ctx.res, 400, { error: 'bad_request' }, NO_STORE);
  }
  const challenge = takeChallenge(`login:${challengeId}`);
  if (!challenge) return sendJson(ctx.res, 400, { error: 'challenge_expired' }, NO_STORE);
  const rawId = pick(outer.rawId, outer.id);
  const cred = rawId ? creds.byId(rawId) : null;
  const user = cred ? users.byId(cred.user_id) : null;
  if (!cred || !user || user.disabled) {
    return sendJson(ctx.res, 404, { error: 'no_credentials' }, NO_STORE);
  }
  let result;
  try {
    result = verifyAssertion({
      credentialPublicKey: cred.public_key,
      authenticatorData,
      clientDataJSON,
      signature,
    }, {
      expectedChallenge: challenge,
      expectedOrigin: new URL(rt.issuer).origin,
      rpId: rpId(),
      expectedType: 'webauthn.get',
    });
  } catch (e) {
    logger.warn('Passkey 登录校验失败', { id: cred.id, code: e.code, err: e.message });
    return sendJson(ctx.res, 401, { error: 'invalid_credentials' }, NO_STORE);
  }
  // 两端均为 0 表示认证器不支持计数器;其余情况必须严格递增。
  if ((result.signCount !== 0 || cred.counter !== 0) && result.signCount <= cred.counter) {
    record(ctx, 'auth.passkey_clone_suspect', cred.id, { actor: user.username });
    logger.warn('Passkey 计数器回退,疑似克隆', { id: cred.id, stored: cred.counter, got: result.signCount });
    return sendJson(ctx.res, 409, { error: 'credential_cloned' }, NO_STORE);
  }
  creds.updateCounter(cred.id, result.signCount);
  startSession(ctx.res, user, undefined, sessionMeta(ctx));
  record(ctx, 'auth.passkey_login', user.username, { actor: user.username });
  logger.info('Passkey 登录成功', { username: user.username });
  return sendJson(ctx.res, 200, { ok: true, user: { username: user.username, name: user.name } }, NO_STORE);
}

/** POST /account/webauthn/:id/delete —— 删除自己的凭据(表单提交,CSRF 校验) */
export function deleteCredential(ctx) {
  if (!ctx.session || typeof ctx.body?._csrf !== 'string' || ctx.body._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/account?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  const row = creds.byId(ctx.params.id);
  const removed = !!row && creds.remove(row.id, ctx.user.id);
  if (removed) {
    record(ctx, 'account.passkey_deleted', row.name);
    logger.info('Passkey 已删除', { user: ctx.user.username, name: row.name });
  }
  redirect(ctx.res, '/account?' + (removed
    ? 'msg=' + encodeURIComponent(`Passkey「${row.name}」已删除。`)
    : 'err=' + encodeURIComponent('未找到该 Passkey。')));
}
