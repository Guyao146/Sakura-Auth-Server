/**
 * WebAuthn(ES256)零依赖验证内核:
 * - 最小 CBOR 解码器(认证器数据只含 major 0-7;浮点/simple 不支持,出现即抛错)
 * - authenticatorData 按 WebAuthn Level 2 §6.1 布局解析
 * - COSE EC2(P-256)公钥 → JWK,经 crypto.createPublicKey/crypto.verify 验签
 *
 * 旗标位按规范:UP=0x01(用户在场)、UV=0x04(已验证)、AT=0x40(带凭据数据)、ED=0x80(带扩展)。
 * 无密码登录必须由认证器完成用户验证(UV),注册与登录均强制 UP + UV。
 */
import crypto from 'node:crypto';
import { timingSafeEqStr } from './crypto.js';

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_AT = 0x40;
export const FLAG_ED = 0x80;

/** 构造带 code 的 Error,便于服务层映射 HTTP 错误 */
const fail = (code, message) => Object.assign(new Error(message || code), { code });

/** 任意输入 → Buffer(接口层统一传 base64url 字符串) */
const toBuf = (v) => {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return Buffer.from(v);
  return Buffer.from(String(v || ''), 'base64url');
};

/**
 * CBOR 前缀解码:解码 buf 起始的第一个数据项,返回 { value, size }。
 * size 供 authenticatorData 定位 COSE key 之后的 extensions 段。
 */
export function cborDecodePrefix(buf) {
  if (!Buffer.isBuffer(buf)) throw fail('cbor_invalid');
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let pos = 0;
  const key = (k) => {
    if (typeof k === 'number' || typeof k === 'string') return String(k);
    throw fail('cbor_invalid', 'CBOR map 键类型不支持');
  };
  const item = () => {
    if (pos >= buf.length) throw fail('cbor_truncated');
    const ib = buf[pos++];
    const mt = ib >> 5;
    const ai = ib & 31;
    let n;
    if (ai < 24) n = ai;
    else if (ai === 24) n = buf[pos++];
    else if (ai === 25) { n = dv.getUint16(pos); pos += 2; }
    else if (ai === 26) { n = dv.getUint32(pos); pos += 4; }
    else if (ai === 27) { n = Number(dv.getBigUint64(pos)); pos += 8; }
    else throw fail('cbor_invalid', 'CBOR 不定长/保留项不支持');
    switch (mt) {
      case 0: return n;                                   // 无符号整数
      case 1: return -1 - n;                              // 负整数
      case 2: {                                           // 字节串
        if (pos + n > buf.length) throw fail('cbor_truncated');
        const b = buf.subarray(pos, pos + n);
        pos += n;
        return b;
      }
      case 3: {                                           // 文本串
        if (pos + n > buf.length) throw fail('cbor_truncated');
        const s = buf.subarray(pos, pos + n).toString('utf8');
        pos += n;
        return s;
      }
      case 4: {                                           // 数组
        const a = [];
        for (let i = 0; i < n; i++) a.push(item());
        return a;
      }
      case 5: {                                           // map(键统一转字符串)
        const m = {};
        for (let i = 0; i < n; i++) m[key(item())] = item();
        return m;
      }
      case 6: return item();                              // 标签:跳过标签号取内层值
      default:                                            // major 7:simple/float
        if (n === 20) return false;
        if (n === 21) return true;
        if (n === 22) return null;
        if (n === 23) return undefined;
        throw fail('cbor_invalid', 'CBOR 浮点/简单值不支持(认证器不会发送)');
    }
  };
  const value = item();
  return { value, size: pos };
}

/** 严格 CBOR 解码:解码后不允许有剩余字节 */
export function cborDecode(buf) {
  const { value, size } = cborDecodePrefix(buf);
  if (size !== buf.length) throw fail('cbor_trailing', 'CBOR 数据项后有多余字节');
  return value;
}

/**
 * 解析 authenticatorData:rpIdHash(32B) + flags(1B) + signCount(4B BE)
 * [ + attestedCredentialData(aaguid 16B + credIdLen 2B BE + credId + CBOR COSE key)(AT 置位时)
 *   + extensions(CBOR map)(ED 置位时) ]
 */
export function parseAuthData(authData) {
  const buf = toBuf(authData);
  if (buf.length < 37) throw fail('auth_data_invalid');
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf[32];
  const signCount = buf.readUInt32BE(33);
  let off = 37;
  let attestedCredential = null;
  if (flags & FLAG_AT) {
    if (buf.length < off + 18) throw fail('auth_data_invalid');
    const aaguid = buf.subarray(off, off + 16);
    const credIdLen = buf.readUInt16BE(off + 16);
    off += 18;
    if (buf.length < off + credIdLen) throw fail('auth_data_invalid');
    const credentialId = buf.subarray(off, off + credIdLen);
    off += credIdLen;
    // 先按 CBOR 解码定位长度(顺带校验格式),但保留原始字节:入库/验签都以 COSE 字节为准
    const { size } = cborDecodePrefix(buf.subarray(off));
    const cosePublicKey = buf.subarray(off, off + size);
    off += size;
    attestedCredential = { aaguid, credentialId, cosePublicKey };
  }
  if (flags & FLAG_ED) {
    const { size } = cborDecodePrefix(buf.subarray(off)); // 扩展内容本服务不消费,仅按 CBOR 跳过
    off += size;
  }
  if (off !== buf.length) throw fail('auth_data_invalid');
  return { rpIdHash, flags, signCount, attestedCredential, hasED: !!(flags & FLAG_ED) };
}

/** COSE 公钥(EC2/P-256/ES256)→ JWK;不支持的 kty/alg/crv 抛错 */
export function coseToJwk(cose) {
  const g = (k) => cose?.[String(k)];
  if (g(1) !== 2) throw fail('cose_kty_unsupported', '仅支持 EC2 公钥(kty=2)');
  if (g(3) !== undefined && g(3) !== -7) throw fail('cose_alg_unsupported', '仅支持 ES256(alg=-7)');
  if (g(-1) !== 1) throw fail('cose_crv_unsupported', '仅支持 P-256 曲线');
  const x = g(-2);
  const y = g(-3);
  if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) {
    throw fail('cose_key_invalid');
  }
  return { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') };
}

const coseToKeyObject = (coseBuf) =>
  crypto.createPublicKey({ key: coseToJwk(cborDecode(coseBuf)), format: 'jwk' });

/** 校验 clientData(共享于注册/断言):type / challenge(base64url 恒时等值)/ origin */
function checkClientData(clientDataJSON, { expectedType, expectedChallenge, expectedOrigin }) {
  let cd;
  try {
    cd = JSON.parse(toBuf(clientDataJSON).toString('utf8'));
  } catch {
    throw fail('client_data_invalid');
  }
  if (!cd || typeof cd !== 'object') throw fail('client_data_invalid');
  if (cd.type !== expectedType) throw fail('type_mismatch');
  if (typeof cd.challenge !== 'string' || !timingSafeEqStr(cd.challenge, String(expectedChallenge || ''))) {
    throw fail('challenge_mismatch');
  }
  if (cd.origin !== expectedOrigin || cd.crossOrigin === true) throw fail('origin_mismatch');
  return cd;
}

/**
 * 验证 assertion(登录):签名覆盖 authenticatorData ‖ SHA256(clientDataJSON)。
 * 成功返回 { flags, signCount };任何一步失败抛带 code 的 Error。
 */
export function verifyAssertion({ credentialPublicKey, authenticatorData, clientDataJSON, signature }, {
  expectedChallenge, expectedOrigin, rpId, expectedType = 'webauthn.get',
}) {
  const cdBuf = toBuf(clientDataJSON);
  checkClientData(cdBuf, { expectedType, expectedChallenge, expectedOrigin });
  const authData = toBuf(authenticatorData);
  const parsed = parseAuthData(authData);
  if (!(parsed.flags & FLAG_UP)) throw fail('user_presence_required');
  if (!(parsed.flags & FLAG_UV)) throw fail('user_verification_required');
  if (!parsed.rpIdHash.equals(crypto.createHash('sha256').update(rpId).digest())) {
    throw fail('rp_id_mismatch');
  }
  const clientHash = crypto.createHash('sha256').update(cdBuf).digest();
  let ok;
  try {
    ok = crypto.verify('sha256', Buffer.concat([authData, clientHash]),
      coseToKeyObject(toBuf(credentialPublicKey)), toBuf(signature));
  } catch {
    throw fail('signature_invalid');
  }
  if (!ok) throw fail('signature_invalid');
  return { flags: parsed.flags, signCount: parsed.signCount };
}

/**
 * 解析并验证注册 attestation(fmt='none' 或 'packed' 自签/含 x5c 证书,跳过链校验)。
 * 成功返回 { credentialId, cosePublicKey, signCount, aaguid }(均为 Buffer)。
 */
export function parseAttestation({ attestationObject, clientDataJSON, expectedChallenge, expectedOrigin, rpId }) {
  const cdBuf = toBuf(clientDataJSON);
  checkClientData(cdBuf, { expectedType: 'webauthn.create', expectedChallenge, expectedOrigin });
  const att = cborDecode(toBuf(attestationObject));
  if (!att || typeof att !== 'object' || !Buffer.isBuffer(att.authData)) throw fail('attestation_invalid');
  const parsed = parseAuthData(att.authData);
  if (!(parsed.flags & FLAG_UP)) throw fail('user_presence_required');
  if (!(parsed.flags & FLAG_UV)) throw fail('user_verification_required');
  if (!parsed.rpIdHash.equals(crypto.createHash('sha256').update(rpId).digest())) throw fail('rp_id_mismatch');
  if (!parsed.attestedCredential) throw fail('attested_credential_missing');
  const { attestedCredential: { credentialId, cosePublicKey, aaguid } } = parsed;
  const clientHash = crypto.createHash('sha256').update(cdBuf).digest();
  const signed = Buffer.concat([att.authData, clientHash]);
  const fmt = att.fmt;
  if (fmt === 'none') {
    // 无证明格式:不校验来源,直接信任 authData 内的 COSE key
  } else if (fmt === 'packed') {
    const attStmt = att.attStmt || {};
    if (attStmt.alg !== undefined && attStmt.alg !== -7) throw fail('attestation_alg_unsupported');
    let keyObject;
    if (Array.isArray(attStmt.x5c) && attStmt.x5c.length) {
      // 证书路径:用叶子证书公钥验签(跳过信任链校验,满足「自签/企业证」两类)
      const der = toBuf(attStmt.x5c[0]);
      try {
        keyObject = new crypto.X509Certificate(der).publicKey;
      } catch {
        const pem = `-----BEGIN CERTIFICATE-----\n${der.toString('base64')}\n-----END CERTIFICATE-----`;
        keyObject = new crypto.X509Certificate(pem).publicKey;
      }
    } else {
      keyObject = coseToKeyObject(cosePublicKey); // 自证明:用凭据自身公钥
    }
    let ok;
    try {
      ok = crypto.verify('sha256', signed, keyObject, toBuf(attStmt.sig));
    } catch {
      throw fail('attestation_invalid');
    }
    if (!ok) throw fail('attestation_invalid');
  } else {
    throw fail('attestation_fmt_unsupported');
  }
  coseToKeyObject(cosePublicKey);
  if (!credentialId.length) throw fail('attested_credential_missing');
  return { credentialId, cosePublicKey, signCount: parsed.signCount, aaguid };
}
