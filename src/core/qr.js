/**
 * 零依赖 QR 编码器(ISO/IEC 18004 最小子集)。
 * 范围:byte mode(UTF-8 字节)/ 版本 1-10 自动选择 / 纠错等级 M / 掩码 0-7 按四条惩罚规则打分取最小。
 * 产出:布尔矩阵(第 0 行第 0 列起,true 为深色)与内联 SVG(深色用 var(--heading),背景透明)。
 * 全部为纯函数,除 GF 表初始化外无模块级状态。
 */

/* ---------- GF(256) 伽罗瓦域(本原多项式 x^8+x^2+x+1 = 0x11D) ---------- */
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}

/** GF(256) 乘法 */
export const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]);

/* ---------- Reed-Solomon 纠错(系统码:数据码字在前,余数在后) ---------- */

/** RS 生成多项式 g(x) = Π_{i=0}^{ecLen-1} (x - α^i),系数最高次在前,首项恒为 1 */
export function rsGeneratorPoly(ecLen) {
  let poly = [1];
  for (let i = 0; i < ecLen; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j]; // × x
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]); // × α^i
    }
    poly = next;
  }
  return poly;
}

/** 数据码字 → ecLen 个纠错码字(多项式除法余数,综合除法) */
export function rsEncode(data, ecLen) {
  const gen = rsGeneratorPoly(ecLen);
  const buf = new Uint8Array(data.length + ecLen);
  buf.set(data);
  for (let i = 0; i < data.length; i++) {
    const factor = buf[i];
    if (factor === 0) continue;
    for (let j = 1; j < gen.length; j++) buf[i + j] ^= gfMul(gen[j], factor);
  }
  return buf.slice(data.length);
}

/* ---------- 版本参数(纠错等级 M,ISO/IEC 18004 表 13-15 与附录 E) ---------- */
// groups: [块数, 每块数据码字数];ec: 每块纠错码字数
const VERSION_M = [
  { ec: 10, groups: [[1, 16]] },            // V1
  { ec: 16, groups: [[1, 28]] },            // V2
  { ec: 26, groups: [[1, 44]] },            // V3
  { ec: 18, groups: [[2, 32]] },            // V4
  { ec: 24, groups: [[2, 43]] },            // V5
  { ec: 16, groups: [[4, 27]] },            // V6
  { ec: 18, groups: [[4, 31]] },            // V7
  { ec: 22, groups: [[2, 38], [2, 39]] },   // V8
  { ec: 22, groups: [[3, 36], [2, 37]] },   // V9
  { ec: 26, groups: [[4, 43], [1, 44]] },   // V10
].map(({ ec, groups }) => ({
  ec,
  groups,
  dataLen: groups.reduce((sum, [count, len]) => sum + count * len, 0),
}));

// 校正图形中心坐标(Table E.1);版本 1 无
const ALIGNMENT = [
  null,
  [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];

/** 纠错等级 M 下各版本 byte mode 容量(字节) */
export const byteCapacity = (version) =>
  Math.floor((VERSION_M[version - 1].dataLen * 8 - 4 - (version <= 9 ? 8 : 16)) / 8);

/** 按字节数选最小可用版本(1-10),放不下抛 RangeError */
export function selectVersion(byteLen) {
  for (let v = 1; v <= 10; v++) if (byteLen <= byteCapacity(v)) return v;
  throw new RangeError(`内容 ${byteLen} 字节,超出 QR 版本 1-10(纠错 M)的容量上限 ${byteCapacity(10)} 字节`);
}

/* ---------- 数据码字:模式指示 + 计数 + 数据 + 终止符 + 填充 ---------- */
function buildDataCodewords(bytes, version) {
  const cap = VERSION_M[version - 1].dataLen;
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  push(0b0100, 4); // 模式指示:byte mode
  push(bytes.length, version <= 9 ? 8 : 16); // 字符计数指示
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, cap * 8 - bits.length)); // 终止符(最多 4 位)
  while (bits.length % 8 !== 0) bits.push(0); // 补齐字节边界
  const out = new Uint8Array(cap);
  const padStart = bits.length / 8;
  for (let i = 0; i < padStart; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i * 8 + j];
    out[i] = byte;
  }
  for (let i = padStart; i < cap; i++) out[i] = (i - padStart) % 2 === 0 ? 0xec : 0x11; // 填充字节
  return out;
}

/** 文本 → { version, blocks: [{data, ec}], codewords(块间交织后的最终码字)}(测试与内部用) */
export function encodeText(text) {
  const bytes = new TextEncoder().encode(String(text));
  const version = selectVersion(bytes.length);
  const spec = VERSION_M[version - 1];
  const data = buildDataCodewords(bytes, version);
  const blocks = [];
  let off = 0;
  for (const [count, len] of spec.groups) {
    for (let k = 0; k < count; k++) {
      const part = data.slice(off, off + len);
      off += len;
      blocks.push({ data: part, ec: rsEncode(part, spec.ec) });
    }
  }
  const cw = [];
  const maxLen = Math.max(...blocks.map((b) => b.data.length));
  for (let i = 0; i < maxLen; i++)
    for (const b of blocks) if (i < b.data.length) cw.push(b.data[i]);
  for (let i = 0; i < spec.ec; i++)
    for (const b of blocks) cw.push(b.ec[i]);
  return { version, blocks, codewords: Uint8Array.from(cw) };
}

/* ---------- 功能图形 ---------- */
function drawFinder(rows, isFn, r0, c0) {
  const size = rows.length;
  for (let dr = -1; dr <= 7; dr++) {
    for (let dc = -1; dc <= 7; dc++) {
      const r = r0 + dr;
      const c = c0 + dc;
      if (r < 0 || r >= size || c < 0 || c >= size) continue;
      const d = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
      rows[r][c] = d !== 2 && d !== 4; // 外框与 3×3 中心深色,过渡环与分隔符浅色
      isFn[r][c] = true;
    }
  }
}

function drawAlignment(rows, isFn, r0, c0) {
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      rows[r0 + dr][c0 + dc] = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
      isFn[r0 + dr][c0 + dc] = true;
    }
  }
}

function drawPatterns(rows, isFn, version) {
  const size = rows.length;
  drawFinder(rows, isFn, 0, 0);
  drawFinder(rows, isFn, 0, size - 7);
  drawFinder(rows, isFn, size - 7, 0);
  for (let i = 8; i < size - 8; i++) { // 时序图形:第 6 行/列,深浅交替
    const dark = i % 2 === 0;
    rows[6][i] = dark;
    isFn[6][i] = true;
    rows[i][6] = dark;
    isFn[i][6] = true;
  }
  const centers = ALIGNMENT[version - 1];
  if (centers) {
    const last = centers.length - 1;
    for (let i = 0; i < centers.length; i++)
      for (let j = 0; j < centers.length; j++)
        if (!((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)))
          drawAlignment(rows, isFn, centers[i], centers[j]); // 与 finder 重叠的三个位置省略
  }
}

/* ---------- 格式信息:BCH(15,5),与掩码模板 0x5412 异或(等级 M 的格式位为 00) ---------- */
const FORMAT_LEVEL_M = 0b00;
const G15 = 0b10100110111;
const G15_MASK = 0b101010000010010;

const formatBits = (mask) => {
  const data = (FORMAT_LEVEL_M << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ G15_MASK;
};

function drawFormat(rows, isFn, mask) {
  const size = rows.length;
  const bits = formatBits(mask);
  const bit = (i) => ((bits >>> i) & 1) === 1;
  const set = (r, c, v) => { rows[r][c] = v; isFn[r][c] = true; };
  for (let i = 0; i <= 5; i++) set(i, 8, bit(i)); // 第一份:列 8(行 0-5)
  set(7, 8, bit(6));
  set(8, 8, bit(7));
  set(8, 7, bit(8)); // 行 8(列 7)
  for (let i = 9; i < 15; i++) set(8, 14 - i, bit(i)); // 行 8(列 5-0)
  for (let i = 0; i < 8; i++) set(8, size - 1 - i, bit(i)); // 第二份:行 8(右上侧)
  for (let i = 8; i < 15; i++) set(size - 15 + i, 8, bit(i)); // 列 8(左下侧)
  set(size - 8, 8, true); // 固定深色模块
}

/* ---------- 版本信息(版本 ≥7):BCH(18,6) ---------- */
const versionBits = (version) => {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | rem;
};

function drawVersion(rows, isFn, version) {
  if (version < 7) return;
  const size = rows.length;
  const bits = versionBits(version);
  for (let i = 0; i < 18; i++) {
    const v = ((bits >>> i) & 1) === 1;
    const a = Math.floor(i / 3); // 0-5
    const b = (i % 3) + size - 11; // size-11..size-9
    rows[a][b] = v;
    isFn[a][b] = true; // 右上块
    rows[b][a] = v;
    isFn[b][a] = true; // 左下块
  }
}

/* ---------- 掩码(ISO/IEC 18004 8.8.2 的 8 种条件) ---------- */
const MASKS = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => ((r >> 1) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r * c) % 3) + ((r + c) % 2)) % 2 === 0,
];

function placeData(rows, isFn, codewords, mask) {
  const size = rows.length;
  const maskFn = MASKS[mask];
  let row = size - 1;
  let inc = -1; // 自底向上开始,逐对列zigzag
  let byteIdx = 0;
  let bitIdx = 7;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col -= 1; // 避开第 6 列时序列
    for (;;) {
      for (let c = 0; c < 2; c++) {
        if (!isFn[row][col - c]) {
          let dark = byteIdx < codewords.length && ((codewords[byteIdx] >>> bitIdx) & 1) === 1;
          if (maskFn(row, col - c)) dark = !dark;
          rows[row][col - c] = dark;
          if (--bitIdx === -1) {
            byteIdx += 1;
            bitIdx = 7;
          }
        }
      }
      row += inc;
      if (row < 0 || row >= size) { // 触边换向
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
}

/* ---------- 掩码打分:四条惩罚规则 ---------- */
const PAT_A = 0b10111010000; // 1:1:3:1:1 特征 + 右侧 4 浅
const PAT_B = 0b00001011101; // 左侧 4 浅 + 1:1:3:1:1 特征

function penalty(rows) {
  const size = rows.length;
  let score = 0;
  const scan = (get) => {
    let run = 1; // 规则 1:行/列同色游程 ≥5 → 3 + (长度-5) 分
    for (let i = 1; i < size; i++) {
      if (get(i) === get(i - 1)) {
        run += 1;
        if (run === 5) score += 3;
        else if (run > 5) score += 1;
      } else run = 1;
    }
    let win = 0; // 规则 3:1:1:3:1:1 特征串(含两侧 4 浅,允许重叠)
    for (let i = 0; i < size; i++) {
      win = ((win << 1) | (get(i) ? 1 : 0)) & 0x7ff;
      if (i >= 10 && (win === PAT_A || win === PAT_B)) score += 40;
    }
  };
  for (let r = 0; r < size; r++) scan((c) => rows[r][c]);
  for (let c = 0; c < size; c++) scan((r) => rows[r][c]);
  for (let r = 0; r < size - 1; r++) // 规则 2:2×2 同色块,每处 3 分
    for (let c = 0; c < size - 1; c++) {
      const v = rows[r][c];
      if (rows[r][c + 1] === v && rows[r + 1][c] === v && rows[r + 1][c + 1] === v) score += 3;
    }
  let dark = 0; // 规则 4:深色占比每偏离 50% 达 5% 记 10 分
  for (const line of rows) for (const v of line) if (v) dark += 1;
  const total = size * size;
  score += Math.floor(Math.abs(dark * 20 - total * 10) / (total * 5)) * 10;
  return score;
}

function buildMatrix(version, codewords, mask) {
  const size = 17 + version * 4;
  const rows = Array.from({ length: size }, () => new Array(size).fill(null));
  const isFn = Array.from({ length: size }, () => new Array(size).fill(false));
  drawPatterns(rows, isFn, version);
  drawVersion(rows, isFn, version);
  drawFormat(rows, isFn, mask);
  placeData(rows, isFn, codewords, mask);
  return rows;
}

/**
 * 文本 → QR 矩阵。
 * 返回 { size, version, mask, matrix: boolean[][], get(r, c) }:
 * matrix/get 第 0 行第 0 列起,true 为深色模块。
 */
export function qrMatrix(text) {
  const { version, codewords } = encodeText(text);
  let best = null;
  let bestMask = 0;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const rows = buildMatrix(version, codewords, mask);
    const score = penalty(rows);
    if (score < bestScore) {
      bestScore = score;
      best = rows;
      bestMask = mask;
    }
  }
  return { size: best.length, version, mask: bestMask, matrix: best, get: (r, c) => best[r][c] };
}

/**
 * 文本 → 内联 SVG(width/height = size 像素,viewBox 含 4 模块静区)。
 * 深色模块 fill 用 var(--heading) 随明暗主题切换,背景透明,shape-rendering 保证模块锐利。
 */
export function qrSvg(text, size = 132) {
  const { matrix } = qrMatrix(text);
  const n = matrix.length;
  const quiet = 4;
  let d = '';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n;) {
      if (!matrix[r][c]) {
        c += 1;
        continue;
      }
      let run = 1;
      while (c + run < n && matrix[r][c + run]) run += 1;
      d += `M${c + quiet} ${r + quiet}h${run}v1h-${run}z`; // 合并横向游程,压缩路径
      c += run;
    }
  }
  const dim = n + quiet * 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges" role="img" aria-label="两步验证二维码"><path style="fill:var(--heading)" d="${d}"/></svg>`;
}
