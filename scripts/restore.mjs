/**
 * 恢复备份:npm run restore -- <备份目录或 .tar.gz> [--force]
 *
 * 流程:
 *   1. 校验备份存在且包含 idp.sqlite(.tar.gz 先解到临时目录);
 *   2. 未加 --force 时仅打印提示(「请先停止服务再恢复」)并退出 —— 防误操作;
 *   3. 恢复前自动把现有数据目录改名为 {DATA_DIR}-before-restore-<时间戳>/(整目录改名,旧数据含历史备份全部保留);
 *   4. 新建数据目录,把 idp.sqlite 覆盖写入、uploads/ 合并覆盖(备份内没有的文件不动旧目录 —— 旧目录已整体改名保留);
 *   5. 成功提示(含旧数据位置;历史备份随旧目录一并保留,可按需移回)。
 *
 * 零依赖;解包用系统 tar(Windows 10+/Ubuntu 自带),不可用时给出明确错误。
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');

const usage = () => {
  console.log([
    '用法:node scripts/restore.mjs <备份目录或 .tar.gz> [--force]',
    '',
    '  <备份目录或 .tar.gz>  data/backups/ 下的 sakuraid-backup-* 目录或同名 .tar.gz',
    '  --force              确认已停止服务并覆盖现有数据(不加则仅打印提示不执行)',
    '',
    '说明:恢复前会把现有数据目录整体改名为 {DATA_DIR}-before-restore-<时间戳>/ 作为自动备份;',
    '      恢复内容为 idp.sqlite(VACUUM INTO 快照)与 uploads/(合并覆盖)。',
  ].join('\n'));
};

const die = (msg) => { console.error(`恢复失败:${msg}`); process.exit(1); };

/* ---------- 参数解析 ---------- */
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h') || args.length === 0) {
  usage();
  process.exit(args.length === 0 ? 1 : 0);
}
const force = args.includes('--force');
const target = args.find((a) => !a.startsWith('--'));
if (!target) die('请指定备份目录或 .tar.gz 文件(见 --help)。');

/* ---------- 定位备份源:目录 / tar.gz / 目录内嵌 sakuraid-backup 子目录 ---------- */
const sourceRaw = path.resolve(target);
if (!fs.existsSync(sourceRaw)) die(`备份不存在:${sourceRaw}`);

let tmpDir = null; // tar.gz 解包临时目录(结束时清理)
let source = sourceRaw; // 实际包含 idp.sqlite 的目录
try {
  if (fs.statSync(sourceRaw).isFile()) {
    if (!/\.tar\.gz$/.test(sourceRaw)) die('仅支持备份目录或 .tar.gz 文件(见 --help)。');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sakuraid-restore-'));
    try {
      execFileSync('tar', ['-xzf', sourceRaw, '-C', tmpDir], { stdio: 'pipe' });
    } catch {
      // GNU tar 会把含盘符的 Windows 路径当远程主机名,追加 --force-local 重试(Windows 自带 bsdtar 无此问题)
      try {
        execFileSync('tar', ['--force-local', '-xzf', sourceRaw, '-C', tmpDir], { stdio: 'pipe' });
      } catch {
        die('解压 .tar.gz 失败:系统 tar 不可用或压缩包损坏。');
      }
    }
    const entries = fs.readdirSync(tmpDir);
    // 标准备份 tar 解出单个 sakuraid-backup-*/ 目录;兼容直接把目录内容打包(顶层即 idp.sqlite)的情形
    const inner = entries.find((n) => n.startsWith('sakuraid-backup-') && fs.statSync(path.join(tmpDir, n)).isDirectory());
    source = inner ? path.join(tmpDir, inner) : tmpDir;
  } else if (!fs.existsSync(path.join(sourceRaw, 'idp.sqlite'))) {
    const inner = fs.readdirSync(sourceRaw)
      .filter((n) => n.startsWith('sakuraid-backup-') && fs.existsSync(path.join(sourceRaw, n, 'idp.sqlite')))
      .sort()
      .pop();
    if (inner) source = path.join(sourceRaw, inner);
  }
  if (!fs.existsSync(path.join(source, 'idp.sqlite'))) {
    die(`备份中未找到 idp.sqlite:${source}`);
  }

  /* ---------- 未加 --force:只提示不执行 ---------- */
  if (!force) {
    console.log([
      `即将把备份恢复到数据目录:${DATA_DIR}`,
      `备份来源:${source}`,
      '',
      '⚠ 恢复会覆盖现有数据。请先停止服务再恢复;',
      '  确认无误后,加 --force 参数重新执行本命令。',
    ].join('\n'));
    process.exit(1);
  }

  /* ---------- 恢复前自动备份:现有数据目录整体改名 ---------- */
  const p2 = (n) => String(n).padStart(2, '0');
  const d = new Date();
  const ts = `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}`;
  let beforeDir = `${DATA_DIR}-before-restore-${ts}`;
  for (let i = 2; fs.existsSync(beforeDir); i++) beforeDir = `${DATA_DIR}-before-restore-${ts}-${i}`;
  const hadOldData = fs.existsSync(DATA_DIR);
  if (hadOldData) {
    try {
      fs.renameSync(DATA_DIR, beforeDir);
    } catch (err) {
      die(`无法改名现有数据目录(${err.message})。服务是否仍在运行?请先停止服务再恢复。`);
    }
    console.log(`已自动备份现有数据:${beforeDir}`);
  }

  /* ---------- 覆盖恢复:idp.sqlite + uploads/ 合并 ---------- */
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.copyFileSync(path.join(source, 'idp.sqlite'), path.join(DATA_DIR, 'idp.sqlite'));
  let uploadCount = 0;
  const uploadsSrc = path.join(source, 'uploads');
  if (fs.existsSync(uploadsSrc)) {
    const copyDir = (src, dst) => {
      fs.mkdirSync(dst, { recursive: true });
      for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const s = path.join(src, entry.name), t = path.join(dst, entry.name);
        if (entry.isDirectory()) copyDir(s, t);
        else { fs.copyFileSync(s, t); uploadCount++; }
      }
    };
    copyDir(uploadsSrc, path.join(DATA_DIR, 'uploads'));
  }

  console.log('恢复完成。');
  console.log(`  数据库:idp.sqlite 已恢复到 ${DATA_DIR}`);
  console.log(`  uploads:${uploadCount} 个文件已合并覆盖`);
  if (hadOldData) {
    console.log(`  旧数据(含历史备份)已保留于:${beforeDir}`);
    console.log('  如确认无需回滚,可自行删除该目录;其中的 data/backups 可按需移回。');
  }
  console.log('请重新启动服务。');
} finally {
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
}
