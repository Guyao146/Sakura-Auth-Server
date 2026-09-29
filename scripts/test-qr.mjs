/**
 * QR 编码器自测(ISO/IEC 18004 子集:byte mode / 版本 1-10 / 纠错等级 M)。
 * 运行:node scripts/test-qr.mjs(退出码 0 = 全部通过)
 * 覆盖:版本选择与容量、RS 校验子与生成多项式、finder/时序/校正图形、
 * 格式与版本信息 BCH 回读、确定性与区分度、SVG 输出、otpauth 端到端。
 */
import {
  qrMatrix, qrSvg, encodeText, selectVersion, byteCapacity, gfMul, rsGeneratorPoly,
} from '../src/core/qr.js';

let pass = 0;
let fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) pass += 1;
  else fail += 1;
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${!cond && extra ? '  → ' + extra : ''}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sub = (m, r0, c0, h, w) => m.slice(r0, r0 + h).map((line) => line.slice(c0, c0 + w));
const utf8Len = (s) => new TextEncoder().encode(s).length;
const gfPow = (p) => { let x = 1; for (let i = 0; i < p; i++) x = gfMul(x, 2); return x; }; // α^p

/* ---------- 样本:跨越版本阈值,含中文与多块交织的大版本 ---------- */
const SAMPLES = [
  { text: 'SAKURA', version: 1 },
  { text: 'A'.repeat(14), version: 1 },   // V1 容量上界(14 字节)
  { text: 'A'.repeat(15), version: 2 },   // 跨过阈值
  { text: '樱'.repeat(14), version: 3 },  // 42 字节,V3 容量上界
  { text: 'A'.repeat(43), version: 4 },   // 跨过阈值
  { text: 'Hello, 世界! QR 123.', version: 2 },
  { text: 'A'.repeat(200), version: 10 }, // 5 块交织 + 版本信息
];

/* ---------- 版本选择与容量 ---------- */
ok('容量表(纠错 M):V1=14 V2=26 V3=42 V10=213',
  byteCapacity(1) === 14 && byteCapacity(2) === 26 && byteCapacity(3) === 42 && byteCapacity(10) === 213,
  `实际 ${[1, 2, 3, 10].map((v) => byteCapacity(v)).join('/')}`);
for (const s of SAMPLES) {
  ok(`版本自动选择:${s.text.length} 字符(${utf8Len(s.text)} 字节)→ V${s.version}`,
    encodeText(s.text).version === s.version, `实际 V${encodeText(s.text).version}`);
}
let overlong = false;
try { selectVersion(214); } catch { overlong = true; }
ok('超出 V10 容量(>213 字节)抛 RangeError', overlong);

/* ---------- Reed-Solomon:校验子全零 + 生成多项式根 ---------- */
for (const s of SAMPLES) {
  const { version, blocks } = encodeText(s.text);
  let allZero = true;
  for (const b of blocks) {
    const cw = [...b.data, ...b.ec];
    for (let i = 0; i < b.ec.length; i++) {
      const x = gfPow(i); // α^i
      let sy = 0;
      for (const byte of cw) sy = gfMul(sy, x) ^ byte; // Horner 求码字多项式 C(α^i)
      if (sy !== 0) allZero = false;
    }
  }
  ok(`RS 校验子全零:V${version}(${blocks.length} 块 × ecLen ${blocks[0].ec.length})`, allZero);
}
for (const ecLen of [10, 16, 26]) {
  const gen = rsGeneratorPoly(ecLen);
  let rootsOk = gen[0] === 1;
  for (let i = 0; i < ecLen && rootsOk; i++) {
    const x = gfPow(i);
    let y = 0;
    for (const c of gen) y = gfMul(y, x) ^ c; // 生成多项式在 α^i 处取值应为 0
    rootsOk = y === 0;
  }
  ok(`RS 生成多项式首一且根含 α^0..α^${ecLen - 1}(ecLen=${ecLen})`, rootsOk);
}

/* ---------- 功能图形(版本 1 与版本 3) ---------- */
const r1 = qrMatrix('A'.repeat(14));   // V1,size 21
const r3 = qrMatrix('樱'.repeat(14));  // V3,size 29
const r10 = qrMatrix('A'.repeat(200)); // V10,size 57
const m1 = r1.matrix;
const m3 = r3.matrix;
const m10 = r10.matrix;

ok('矩阵尺寸 = 17 + 4×版本', m1.length === 21 && m3.length === 29 && m10.length === 57,
  `${m1.length}/${m3.length}/${m10.length}`);
const allFilled = (m) => m.every((line) => line.every((v) => typeof v === 'boolean'));
ok('所有模块均已填充(布尔,无空洞)', [m1, m3, m10].every(allFilled));

const FINDER = Array.from({ length: 7 }, (_, r) =>
  Array.from({ length: 7 }, (_, c) => Math.max(Math.abs(r - 3), Math.abs(c - 3)) !== 2));
const ALIGN5 = Array.from({ length: 5 }, (_, r) =>
  Array.from({ length: 5 }, (_, c) => Math.max(Math.abs(r - 2), Math.abs(c - 2)) !== 1));
const findersOk = (m) => {
  const s = m.length;
  return eq(sub(m, 0, 0, 7, 7), FINDER)
    && eq(sub(m, 0, s - 7, 7, 7), FINDER)
    && eq(sub(m, s - 7, 0, 7, 7), FINDER);
};
ok('V1 三个 finder 图形(7×7 外框+中心)正确', findersOk(m1));
ok('V3 三个 finder 图形正确', findersOk(m3));

const separatorsOk = (m) => {
  const s = m.length;
  const light = (r, c) => m[r][c] === false;
  for (let i = 0; i < 8; i++) {
    if (!light(7, i) || !light(i, 7)) return false;             // 左上分隔
    if (!light(7, s - 8 + i) || !light(i, s - 8)) return false; // 右上分隔
    if (!light(s - 8 + i, 7) || !light(s - 8, i)) return false; // 左下分隔
  }
  return true;
};
ok('V1/V3 finder 分隔符留白正确', separatorsOk(m1) && separatorsOk(m3));

const timingOk = (m) => {
  const s = m.length;
  for (let i = 8; i < s - 8; i++) {
    if (m[6][i] !== (i % 2 === 0) || m[i][6] !== (i % 2 === 0)) return false;
  }
  return true;
};
ok('V1/V3 时序图形第 6 行/列交替正确', timingOk(m1) && timingOk(m3));

const hasAlign = (m) => {
  for (let r = 0; r + 5 <= m.length; r++)
    for (let c = 0; c + 5 <= m.length; c++)
      if (eq(sub(m, r, c, 5, 5), ALIGN5)) return true;
  return false;
};
ok('V3 校正图形位于 (22,22)(5×5 同心方)', eq(sub(m3, 20, 20, 5, 5), ALIGN5) && hasAlign(m3));
ok('V1 无校正图形', !hasAlign(m1));
ok('固定深色模块位于 (size-8, 8)', m1[13][8] === true && m3[21][8] === true && m10[49][8] === true);

/* ---------- 格式信息:BCH(15,5)+ 掩码模板异或,两份一致 ---------- */
const G15 = 0b10100110111;
const FORMAT_XOR = 0b101010000010010;
const bch15Rem = (v) => {
  for (let i = 14; i >= 10; i--) if ((v >>> i) & 1) v ^= G15 << (i - 10);
  return v;
};
const readFormatA = (m) => { // 第一份:绕左上 finder
  let bits = 0;
  for (let i = 0; i <= 5; i++) if (m[i][8]) bits |= 1 << i;
  if (m[7][8]) bits |= 1 << 6;
  if (m[8][8]) bits |= 1 << 7;
  if (m[8][7]) bits |= 1 << 8;
  for (let i = 9; i < 15; i++) if (m[8][14 - i]) bits |= 1 << i;
  return bits;
};
const readFormatB = (m) => { // 第二份:右上横排 + 左下竖排
  const s = m.length;
  let bits = 0;
  for (let i = 0; i < 8; i++) if (m[8][s - 1 - i]) bits |= 1 << i;
  for (let i = 8; i < 15; i++) if (m[s - 15 + i][8]) bits |= 1 << i;
  return bits;
};
for (const [label, res] of [['V1', r1], ['V3', r3]]) {
  const f1 = readFormatA(res.matrix);
  const f2 = readFormatB(res.matrix);
  const bare = f1 ^ FORMAT_XOR;
  ok(`${label} 格式信息两份一致`, f1 === f2, `${f1} / ${f2}`);
  ok(`${label} 格式信息 BCH(15,5) 余数为 0`, bch15Rem(bare) === 0);
  // 低 10 位是 BCH 余数(任意值),掩码号只从高 5 位数据位读取
  ok(`${label} 格式位 = 等级 M(00)+ 掩码 ${res.mask}(与实际所用掩码一致)`,
    (bare >>> 10) === res.mask, `高5位=${bare >>> 10}`);
}

/* ---------- 版本信息(版本 ≥7):BCH(18,6) ---------- */
const G18 = 0b1111100100101;
const bch18Rem = (v) => {
  for (let i = 17; i >= 12; i--) if ((v >>> i) & 1) v ^= G18 << (i - 12);
  return v;
};
const readVersionTR = (m) => { // 右上块
  const s = m.length;
  let bits = 0;
  for (let i = 0; i < 18; i++) if (m[Math.floor(i / 3)][(i % 3) + s - 11]) bits |= 1 << i;
  return bits;
};
const readVersionBL = (m) => { // 左下块
  const s = m.length;
  let bits = 0;
  for (let i = 0; i < 18; i++) if (m[(i % 3) + s - 11][Math.floor(i / 3)]) bits |= 1 << i;
  return bits;
};
const vbits = readVersionTR(m10);
ok('V10 版本信息两份一致', vbits === readVersionBL(m10));
ok('V10 版本信息 BCH 余数 0 且版本号 = 10', bch18Rem(vbits) === 0 && (vbits >>> 12) === 10);

/* ---------- 确定性与区分度 ---------- */
const URI = 'otpauth://totp/SakuraID:demo?secret=ABCDEF234567';
const again = qrMatrix(URI);
ok('同输入两次生成矩阵完全一致(确定性)', eq(qrMatrix(URI).matrix, again.matrix));
ok('不同输入矩阵不同', !eq(qrMatrix('SAKURA-A').matrix, qrMatrix('SAKURA-B').matrix));
ok('qrMatrix 暴露 get(r,c) 且 (0,0) 为深色', typeof again.get(0, 0) === 'boolean' && again.get(0, 0) === true);

/* ---------- SVG 输出 ---------- */
const svg = qrSvg('https://sakura.example/otpauth?x=樱');
ok('qrSvg 输出内联 SVG,shape-rendering=crispEdges',
  svg.startsWith('<svg ') && svg.includes('shape-rendering="crispEdges"'));
ok('SVG 深色模块用 var(--heading)(随明暗主题切换)', svg.includes('var(--heading)'));
ok('SVG 默认 132px,自定义尺寸生效', svg.includes('width="132"') && svg.includes('height="132"')
  && qrSvg('x', 96).includes('width="96"'));
ok('SVG 背景透明、无外部资源引用(仅内置 xmlns)',
  !/<(rect|image|use|foreignObject|script)/.test(svg) && svg.includes('xmlns="http://www.w3.org/2000/svg"'));
ok('SVG 内容确定性(同输入两次相同)', svg === qrSvg('https://sakura.example/otpauth?x=樱'));

/* ---------- otpauth URI 端到端(与账号页同一形状) ---------- */
const { otpauthUri } = await import('../src/core/totp.js');
const uri = otpauthUri({ secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', username: 'admin', issuer: '樱落统一认证' });
const enc = encodeText(uri);
ok('账号页同款 otpauth URI 可编码(V10,5 块交织)', enc.version === 10 && enc.blocks.length === 5,
  `实际 V${enc.version},${enc.blocks.length} 块`);
ok('otpauth URI 可渲染为 SVG', qrSvg(uri).startsWith('<svg'));

console.log(fail ? `\n${fail} 项失败` : `\n全部通过 ✔(共 ${pass} 项)`);
process.exit(fail ? 1 : 0);
