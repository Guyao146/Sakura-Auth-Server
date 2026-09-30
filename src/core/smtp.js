/**
 * 零依赖 SMTP 客户端(找回密码邮件用)。
 * 流程:connect → EHLO → 服务端支持则 STARTTLS(node:tls 包住现有 socket)
 *   → AUTH PLAIN / AUTH LOGIN → MAIL FROM → RCPT TO → DATA → QUIT。
 * 全程校验响应码,任一阶段失败抛出带阶段标记的 SmtpError。
 * 配置来源:settings 表(配置向导写入)打底,SMTP_* 环境变量优先覆盖,
 * 见 core/runtime.js 的 getSmtpConfig();未配置主机时为开发模式:不连接,完整邮件内容打到日志。
 */
import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import { getSmtpConfig } from './runtime.js';
import { logger } from './logger.js';

/** 带阶段标记的 SMTP 错误 */
export class SmtpError extends Error {
  constructor(stage, detail) {
    super(`SMTP ${stage} 失败:${detail}`);
    this.name = 'SmtpError';
    this.stage = stage;
  }
}

const ehloName = () => (os.hostname() || 'localhost').replace(/[^\w.-]/g, '') || 'localhost';
const b64 = (s) => Buffer.from(String(s), 'utf8').toString('base64');

/**
 * 从字节缓冲中解析一条完整 SMTP 响应。
 * 多行响应以 "ddd-text" 续行、以 "ddd text" 结束。
 * 返回 { rest, code, text } / { error } / null(还不完整)。
 */
function tryParse(buf) {
  const s = buf.toString('latin1'); // 响应为 ASCII;latin1 保证字节与字符一一对应
  let idx = 0;
  for (;;) {
    const nl = s.indexOf('\r\n', idx);
    if (nl === -1) return null;
    const line = s.slice(idx, nl);
    if (/^\d{3} /.test(line) || /^\d{3}$/.test(line)) {
      return { rest: buf.subarray(nl + 2), code: Number(line.slice(0, 3)), text: s.slice(0, nl + 2) };
    }
    if (!/^\d{3}-/.test(line)) return { error: `无法识别的服务器响应「${line.slice(0, 80)}」` };
    idx = nl + 2;
  }
}

/**
 * 在 socket 上挂最小化的响应读取器。SMTP 是严格的一问一答,
 * 用单个 pending promise 排队即可;返回 { read, detach, destroy }。
 */
function attach(socket, timeoutMs) {
  const st = { buf: Buffer.alloc(0), pending: null, dead: false };

  const fail = (err) => {
    if (st.dead) return;
    st.dead = true;
    const p = st.pending;
    st.pending = null;
    if (p) p.reject(err);
  };
  const feed = () => {
    if (!st.pending || st.dead) return;
    const parsed = tryParse(st.buf);
    if (!parsed) return;
    const p = st.pending;
    st.pending = null;
    if (parsed.error) { st.buf = Buffer.alloc(0); p.reject(new SmtpError('协议', parsed.error)); return; }
    st.buf = parsed.rest;
    p.resolve({ code: parsed.code, text: parsed.text });
  };

  const onData = (chunk) => { st.buf = Buffer.concat([st.buf, chunk]); feed(); };
  const onTimeout = () => fail(new SmtpError('网络', `等待响应超过 ${timeoutMs}ms`));
  const onError = (err) => fail(new SmtpError('网络', `连接错误:${err.message}`));
  const onClose = () => fail(new SmtpError('网络', '连接被对端关闭'));

  socket.on('data', onData);
  socket.on('timeout', onTimeout);
  socket.on('error', onError);
  socket.on('close', onClose);

  return {
    read() {
      if (st.dead) return Promise.reject(new SmtpError('网络', '连接已关闭'));
      return new Promise((resolve, reject) => { st.pending = { resolve, reject }; feed(); });
    },
    /** STARTTLS 升级前摘掉监听,把裸 socket 交给 node:tls */
    detach() {
      socket.removeListener('data', onData);
      socket.removeListener('timeout', onTimeout);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      st.dead = true;
      const p = st.pending;
      st.pending = null;
      if (p) p.reject(new SmtpError('STARTTLS', '升级 TLS 时连接被重置'));
    },
    destroy() {
      st.dead = true;
      socket.destroy();
    },
  };
}

function writeLine(socket, line) {
  return new Promise((resolve, reject) => {
    socket.write(line + '\r\n', 'utf8', (err) => (err ? reject(new SmtpError('网络', `发送失败:${err.message}`)) : resolve()));
  });
}

function connectTcp(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new SmtpError('连接', `连接 ${host}:${port} 超时(${timeoutMs}ms)`));
    }, timeoutMs);
    socket.once('connect', () => { clearTimeout(timer); socket.setTimeout(timeoutMs); resolve(socket); });
    socket.once('error', (err) => { clearTimeout(timer); reject(new SmtpError('连接', `无法连接 ${host}:${port}(${err.message})`)); });
  });
}

function upgradeTls(socket, host, timeoutMs) {
  return new Promise((resolve, reject) => {
    // 自建 IdP 常对接自签证书的内部邮件网关:保留 STARTTLS 加密,但不校验证书链
    const tlsSocket = tls.connect({ socket, servername: host, rejectUnauthorized: false }, () => resolve(tlsSocket));
    tlsSocket.setTimeout(timeoutMs);
    tlsSocket.once('error', (err) => reject(new SmtpError('STARTTLS', `TLS 握手失败(${err.message})`)));
  });
}

/** 组装 RFC 5322 信头 + 纯文本正文(CRLF;Subject 用 RFC 2047 B 编码) */
export function buildMessage({ from, to, subject, text }) {
  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: =?UTF-8?B?${b64(subject)}?=`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    `Date: ${new Date().toUTCString()}`,
  ];
  const body = String(text ?? '').replace(/\r?\n/g, '\r\n');
  return headers.join('\r\n') + '\r\n\r\n' + body;
}

/**
 * 发送一封纯文本邮件。mail 字段缺省时回落到合并后的 SMTP 配置
 * (settings 表打底、SMTP_* 环境变量优先,见 runtime.getSmtpConfig)。
 * 未配置 host 时进入开发模式:完整内容打日志,正常返回 { dev: true }。
 */
export async function sendMail(mail, opts = {}) {
  const cfg = getSmtpConfig();
  const host = mail.host ?? cfg.host;
  const to = String(mail.to || '').trim();
  const subject = String(mail.subject || '');
  const text = String(mail.text ?? '');

  if (!host) {
    // 开发模式:不连接,把完整邮件内容(收件人/主题/正文/重置链接)输出到日志
    logger.info('[开发模式] 未配置 SMTP 主机,邮件内容如下', {
      to,
      subject,
      text,
      from: mail.from || cfg.from,
    });
    return { dev: true };
  }

  const port = mail.port ?? cfg.port;
  const user = mail.user ?? cfg.user;
  const pass = mail.pass ?? cfg.pass;
  const from = String(mail.from || cfg.from || 'noreply@sakura.local').replace(/^<|>$/g, '');
  const toAddr = to.replace(/^<|>$/g, '');
  const timeoutMs = Number(opts.timeoutMs) || 10000;

  let socket = await connectTcp(host, port, timeoutMs);
  let conn = attach(socket, timeoutMs);
  try {
    /** 等待响应并校验响应码,不符则抛带阶段的错误 */
    const expect = async (stage, okCodes) => {
      const r = await conn.read();
      if (!okCodes.includes(r.code)) {
        const last = r.text.trim().split('\r\n').pop();
        throw new SmtpError(stage, `期望 ${okCodes.join('/')},实际 ${r.code} —— ${last}`);
      }
      return r;
    };
    const cmd = async (line, stage, okCodes) => {
      await writeLine(socket, line);
      return expect(stage, okCodes);
    };

    await expect('连接', [220]); // 服务端问候
    let ehlo = await cmd(`EHLO ${ehloName()}`, 'EHLO', [250]);
    const capLines = () => ehlo.text.split('\r\n')
      .map((l) => l.replace(/^250[ -]/i, '').trim()).filter(Boolean);

    // STARTTLS:仅当服务端在 EHLO 能力中声明时启用,用 node:tls 包住现有 socket
    if (capLines().some((l) => l.toUpperCase().split(/\s+/).includes('STARTTLS'))) {
      await cmd('STARTTLS', 'STARTTLS', [220]);
      conn.detach();
      socket = await upgradeTls(socket, host, timeoutMs);
      conn = attach(socket, timeoutMs);
      ehlo = await cmd(`EHLO ${ehloName()}`, 'EHLO(TLS)', [250]);
    }

    if (user) {
      const authCaps = capLines()
        .filter((l) => /^AUTH\b/i.test(l))
        .flatMap((l) => l.split(/\s+/).slice(1).map((t) => t.toUpperCase()));
      const prefer = [];
      if (authCaps.includes('PLAIN')) prefer.push('PLAIN');
      if (authCaps.includes('LOGIN')) prefer.push('LOGIN');
      if (!prefer.length) prefer.push('PLAIN', 'LOGIN');

      const AUTH_REJECT = [500, 501, 502, 503, 504, 530, 534, 535, 538];
      let authed = false;
      let lastDetail = '服务器未声明任何认证方式';
      for (const mech of prefer) {
        if (mech === 'PLAIN') {
          const r = await cmd(`AUTH PLAIN ${b64(`\0${user}\0${pass}`)}`, 'AUTH', [235, ...AUTH_REJECT]);
          if (r.code === 235) { authed = true; break; }
          lastDetail = `PLAIN 被拒(${r.code})`;
        } else {
          let r = await cmd('AUTH LOGIN', 'AUTH', [334, ...AUTH_REJECT]);
          if (r.code !== 334) { lastDetail = `LOGIN 被拒(${r.code})`; continue; }
          r = await cmd(b64(user), 'AUTH', [334, ...AUTH_REJECT]);
          if (r.code !== 334) { lastDetail = `用户名被拒(${r.code})`; continue; }
          r = await cmd(b64(pass), 'AUTH', [235, 535]);
          if (r.code === 235) { authed = true; break; }
          lastDetail = `密码被拒(${r.code})`;
        }
      }
      if (!authed) throw new SmtpError('AUTH', lastDetail);
    }

    await cmd(`MAIL FROM:<${from}>`, 'MAIL FROM', [250]);
    await cmd(`RCPT TO:<${toAddr}>`, 'RCPT TO', [250, 251]);
    await cmd('DATA', 'DATA', [354]);
    const payload = buildMessage({ from, to: toAddr, subject, text })
      .split('\r\n')
      .map((l) => (l.startsWith('.') ? '.' + l : l)) // 点填充:行首 . 翻倍
      .join('\r\n');
    await writeLine(socket, payload + '\r\n.');
    await expect('DATA(正文)', [250]);
    await cmd('QUIT', 'QUIT', [221]).catch(() => {});
    return { ok: true };
  } finally {
    conn.destroy();
  }
}
