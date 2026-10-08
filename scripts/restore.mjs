/**
 * 恢复备份:npm run restore -- <备份目录或 .tar.gz> [--force]
 *
 * 流程:
 *   1. 校验备份存在且包含 idp.sqlite(.tar.gz 先解到临时目录);
 *   2. 未加 --force 时仅打印提示(「请先停止服务再恢复」)并退出 —— 防误操作;
 *   3. 先复制数据库和 uploads 到同文件系统暂存目录,校验数据库后才操作现有数据;
 *   4. 将现有数据目录改名为 {DATA_DIR}-before-restore-<时间戳>/,再将暂存目录切换为数据目录;
 *   5. 切换失败尝试复位旧目录;成功后旧数据及历史备份仍保留,可按需移回。
 *
 * 零依赖;解包用系统 tar(Windows 10+/Ubuntu 自带),不可用时给出明确错误。
 */
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));

const usage = () => {
  console.log([
    '用法:node scripts/restore.mjs <备份目录或 .tar.gz> [--force]',
    '',
    '  <备份目录或 .tar.gz>  data/backups/ 下的 sakura-auth-server-backup-* 目录或同名 .tar.gz（历史 sakuraid-backup-* 同样兼容）',
    '  --force              确认已停止服务并覆盖现有数据(不加则仅打印提示不执行)',
    '',
    '说明:恢复前会把现有数据目录整体改名为 {DATA_DIR}-before-restore-<时间戳>/ 作为自动备份;',
    '      恢复内容为 idp.sqlite(VACUUM INTO 快照)与 uploads/(以备份内容为准)。',
  ].join('\n'));
};

const die = (msg) => { throw new Error(msg); };

/* ---------- 参数解析 ---------- */
const args = process.argv.slice(2);
if (args.includes('--help') || args.includes('-h') || args.length === 0) {
  usage();
  process.exit(args.length === 0 ? 1 : 0);
}
const force = args.includes('--force');
const target = args.find((a) => !a.startsWith('--'));
if (!target) die('请指定备份目录或 .tar.gz 文件(见 --help)。');

/* 历史前缀 sakuraid-backup-* 与当前前缀 sakura-auth-server-backup-* 均视为有效备份目录名 */
const BACKUP_NAME_RE = /^(?:sakuraid|sakura-auth-server)-backup-\d{8}-\d{6}(-\d+)?$/;
const isBackupName = (n) => BACKUP_NAME_RE.test(n);

/* ---------- 定位备份源:目录 / tar.gz / 目录内嵌备份子目录 ---------- */
const sourceRaw = path.resolve(target);
if (!fs.existsSync(sourceRaw)) die(`备份不存在:${sourceRaw}`);

let stageDir = null; // 与目标同文件系统,先准备并验证,再原子切换
let tmpDir = null; // tar.gz 解包临时目录(结束时清理)
let source = sourceRaw; // 实际包含 idp.sqlite 的目录
try {
  if (fs.statSync(sourceRaw).isFile()) {
    if (!/\.tar\.gz$/.test(sourceRaw)) die('仅支持备份目录或 .tar.gz 文件(见 --help)。');
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sakura-auth-server-restore-'));
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
    // 标准备份 tar 解出单个备份目录;兼容直接把目录内容打包(顶层即 idp.sqlite)的情形
    const inner = entries.find((n) => isBackupName(n) && fs.statSync(path.join(tmpDir, n)).isDirectory());
    source = inner ? path.join(tmpDir, inner) : tmpDir;
  } else if (!fs.existsSync(path.join(sourceRaw, 'idp.sqlite'))) {
    const inner = fs.readdirSync(sourceRaw)
      .filter((n) => isBackupName(n) && fs.existsSync(path.join(sourceRaw, n, 'idp.sqlite')))
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
    throw new Error('请先停止服务再恢复,并加 --force 确认。');
  }

  // 源目录可能位于 DATA_DIR/backups 内,必须在改名旧数据前复制完成。
  fs.mkdirSync(path.dirname(DATA_DIR), { recursive: true });
  stageDir = fs.mkdtempSync(`${DATA_DIR}-restore-stage-`);
  const copyTree = (src, dst) => {
    const stat = fs.lstatSync(src);
    if (stat.isSymbolicLink()) throw new Error('备份不允许包含符号链接');
    if (stat.isDirectory()) {
      fs.mkdirSync(dst, { recursive: true });
      for (const name of fs.readdirSync(src)) copyTree(path.join(src, name), path.join(dst, name));
    } else if (stat.isFile()) fs.copyFileSync(src, dst);
    else throw new Error('备份包含不支持的文件类型');
  };
  copyTree(path.join(source, 'idp.sqlite'), path.join(stageDir, 'idp.sqlite'));
  const candidate = new DatabaseSync(path.join(stageDir, 'idp.sqlite'), { readOnly: true });
  try {
    if (candidate.prepare('PRAGMA quick_check').get().quick_check !== 'ok') throw new Error('备份数据库完整性检查失败');
    candidate.prepare('SELECT id FROM users LIMIT 1').all();
    candidate.prepare('SELECT key FROM settings LIMIT 1').all();
  } finally { candidate.close(); }
  if (fs.existsSync(path.join(source, 'uploads'))) copyTree(path.join(source, 'uploads'), path.join(stageDir, 'uploads'));

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

  // 同文件系统切换;失败立即把旧目录复位,不留下半恢复数据。
  try {
    fs.renameSync(stageDir, DATA_DIR);
    stageDir = null;
  } catch (err) {
    if (hadOldData) fs.renameSync(beforeDir, DATA_DIR);
    throw err;
  }

  console.log('恢复完成。');
  console.log(`  数据库:idp.sqlite 已恢复到 ${DATA_DIR}`);
  console.log('  uploads:已从验证后的备份恢复');
  if (hadOldData) {
    console.log(`  旧数据(含历史备份)已保留于:${beforeDir}`);
    console.log('  如确认无需回滚,可自行删除该目录;其中的 data/backups 可按需移回。');
  }
  console.log('请重新启动服务。');
} catch (err) {
  console.error(`恢复失败:${err.message}`);
  process.exitCode = 1;
} finally {
  if (stageDir) fs.rmSync(stageDir, { recursive: true, force: true });
  if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
}
