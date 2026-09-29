/**
 * SMTP 客户端自测:用 node:net 起进程内假 SMTP 服务器,
 * 断言客户端完整对话顺序与 DATA 内容(收件人、主题编码、正文标记、点填充)。
 * 运行:node scripts/test-smtp.mjs(退出码 0 即全过)
 */
import net from 'node:net';
import { sendMail, buildMessage } from '../src/core/smtp.js';

let failed = 0;
const check = (name, cond, extra = '') => {
  if (!cond) failed++;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? '  → ' + extra : ''}`);
};

const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 假 SMTP 服务器:逐行回应 220/250/334/235/250/354/250,记录完整对话。
 * opts.authMode: 'PLAIN' | 'LOGIN';opts.rejectMailFrom: MAIL FROM 回 550。
 */
function startFakeServer(opts = {}) {
  const log = { cmds: [], data: null };
  const sockets = new Set();
  const server = net.createServer((sock) => {
    sockets.add(sock);
    sock.on('close', () => sockets.delete(sock));
    let buf = '';
    let inData = false;
    let loginStep = 0;
    sock.write('220 fake.local ESMTP ready\r\n');
    sock.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      for (;;) {
        if (inData) {
          const end = buf.indexOf('\r\n.\r\n');
          if (end === -1) return;
          log.data = buf.slice(0, end);
          buf = buf.slice(end + 5);
          inData = false;
          sock.write('250 OK: message accepted\r\n');
          continue;
        }
        const nl = buf.indexOf('\r\n');
        if (nl === -1) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        log.cmds.push(line);
        const upper = line.toUpperCase();
        if (upper.startsWith('EHLO')) {
          sock.write('250-fake.local greets you\r\n');
          sock.write(opts.authMode === 'LOGIN' ? '250-AUTH LOGIN\r\n' : '250-AUTH PLAIN\r\n');
          sock.write('250 SIZE 10485760\r\n');
        } else if (upper.startsWith('AUTH PLAIN')) {
          sock.write('235 2.7.0 authentication successful\r\n');
        } else if (upper.startsWith('AUTH LOGIN')) {
          loginStep = 1;
          sock.write('334 VXNlcm5hbWU6\r\n'); // base64("Username:")
        } else if (loginStep === 1) {
          loginStep = 2;
          sock.write('334 UGFzc3dvcmQ6\r\n'); // base64("Password:")
        } else if (loginStep === 2) {
          loginStep = 0;
          sock.write('235 2.7.0 authentication successful\r\n');
        } else if (upper.startsWith('MAIL FROM')) {
          sock.write(opts.rejectMailFrom ? '550 5.1.0 sender rejected\r\n' : '250 2.1.0 OK\r\n');
        } else if (upper.startsWith('RCPT TO')) {
          sock.write('250 2.1.5 OK\r\n');
        } else if (upper === 'DATA') {
          inData = true;
          sock.write('354 End data with <CR><LF>.<CR><LF>\r\n');
        } else if (upper === 'QUIT') {
          sock.write('221 2.0.0 Bye\r\n');
          sock.end();
        } else {
          sock.write('502 5.5.2 command not recognized\r\n');
        }
      }
    });
  });
  server.kill = () => new Promise((resolve) => {
    for (const s of sockets) s.destroy();
    server.close(() => resolve());
  });
  server.log = log;
  return server;
}

/** 按期望谓词序列在对话中做有序匹配,全部命中返回 true */
function matchSequence(cmds, predicates) {
  let i = 0;
  for (const c of cmds) {
    if (i < predicates.length && predicates[i](c)) i++;
  }
  return i === predicates.length;
}

const MAIL = {
  user: 'user@example.com', pass: 'secret-pass',
  from: 'noreply@example.com', to: 'alice@example.com',
  subject: '樱落统一认证 · 密码重置',
  text: '你的重置链接(30 分钟内有效):\nhttps://idp.example/reset-password?token=RESET-MARKER-123\n.以点开头的行需要点填充',
};

async function testPlainAuth() {
  const server = startFakeServer({ authMode: 'PLAIN' });
  try {
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    await sendMail({ ...MAIL, host: '127.0.0.1', port });
    const { cmds, data } = server.log;

    check('AUTH PLAIN:对话顺序 EHLO→AUTH→MAIL→RCPT→DATA→QUIT',
      matchSequence(cmds, [
        (c) => c.startsWith('EHLO '),
        (c) => c === `AUTH PLAIN ${b64(`\0${MAIL.user}\0${MAIL.pass}`)}`,
        (c) => c === `MAIL FROM:<${MAIL.from}>`,
        (c) => c === `RCPT TO:<${MAIL.to}>`,
        (c) => c === 'DATA',
      ]) && cmds[cmds.length - 1] === 'QUIT',
      JSON.stringify(cmds));

    check('AUTH PLAIN:凭证为 base64(\\0user\\0pass)',
      cmds.some((c) => c === `AUTH PLAIN ${b64(`\0${MAIL.user}\0${MAIL.pass}`)}`));

    check('DATA:包含 From/To 信头',
      data.includes(`From: ${MAIL.from}`) && data.includes(`To: ${MAIL.to}`));

    const m = data.match(/^Subject: =\?UTF-8\?B\?([^?]*)\?=/m);
    check('DATA:Subject 为 =?UTF-8?B?...?= 编码且可解码', !!m && Buffer.from(m[1], 'base64').toString('utf8') === MAIL.subject,
      m ? `解码=${Buffer.from(m[1] || '', 'base64').toString('utf8')}` : '未匹配到 Subject 头');

    check('DATA:正文包含重置链接标记', data.includes('RESET-MARKER-123'));
    check('DATA:正文 CRLF 且行首点已填充',
      data.includes('\r\n..以点开头的行需要点填充') && !data.includes('\r\n.以点开头的行需要点填充\r\n'));
  } finally {
    await server.kill();
  }
}

async function testLoginAuth() {
  const server = startFakeServer({ authMode: 'LOGIN' });
  try {
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    await sendMail({ ...MAIL, host: '127.0.0.1', port });
    const { cmds } = server.log;

    check('AUTH LOGIN:AUTH→用户名→密码 依次 334/334/235',
      matchSequence(cmds, [
        (c) => c === 'AUTH LOGIN',
        (c) => c === b64(MAIL.user),
        (c) => c === b64(MAIL.pass),
      ]),
      JSON.stringify(cmds));
  } finally {
    await server.kill();
  }
}

async function testStageError() {
  const server = startFakeServer({ rejectMailFrom: true });
  try {
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    let caught = null;
    try {
      await sendMail({ ...MAIL, host: '127.0.0.1', port });
    } catch (e) {
      caught = e;
    }
    check('MAIL FROM 被拒时抛带阶段的错误', !!caught && caught.stage === 'MAIL FROM' && /550/.test(caught.message),
      caught ? `${caught.stage}: ${caught.message}` : '未抛错');
  } finally {
    await server.kill();
  }
}

async function testDevMode() {
  const orig = console.log;
  const lines = [];
  console.log = (...args) => lines.push(args.join(' '));
  try {
    // 显式传空 host 强制开发模式(等价于未配置 SMTP_HOST)
    const r = await sendMail({
      host: '', to: 'dev@example.com', subject: '开发模式邮件',
      text: 'DEV-MODE-MARKER https://idp.local/reset-password?token=t-xyz',
    });
    const out = lines.join('\n');
    check('开发模式:不连接、正常返回', r && r.dev === true);
    check('开发模式:日志含收件人/主题/正文与重置链接',
      out.includes('dev@example.com') && out.includes('开发模式邮件')
      && out.includes('DEV-MODE-MARKER') && out.includes('/reset-password?token=t-xyz'));
  } finally {
    console.log = orig;
  }
}

function testBuildMessage() {
  const msg = buildMessage({ from: 'a@b.c', to: 'd@e.f', subject: '中文主题', text: '第一行\n第二行' });
  check('buildMessage:Subject B 编码 + 正文 CRLF 化',
    msg.includes('Subject: =?UTF-8?B?' + b64('中文主题') + '?=') && msg.includes('第一行\r\n第二行'));
}

async function main() {
  console.log('SMTP 客户端自测\n---------------');
  testBuildMessage();
  await testDevMode();
  await testPlainAuth();
  await testLoginAuth();
  await testStageError();
  await sleep(100); // 等 ephemeral 端口收尾
  console.log(failed ? `\n${failed} 项失败` : '\n全部通过 ✔');
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
