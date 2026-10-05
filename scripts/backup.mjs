/**
 * 一键备份:npm run backup(或 node scripts/backup.mjs)
 *
 * 在 {DATA_DIR}/backups/ 下生成 sakuraid-backup-YYYYMMDD-HHmmss/:
 *   - idp.sqlite  用 `VACUUM INTO` 产生一致性快照(不是复制文件,规避 WAL 中间态;WAL/SHM 不带出)
 *   - uploads/    整目录复制(应用 Logo 等上传文件;目录不存在则跳过)
 *   - meta.txt    备份时间 / 版本(package.json)/ issuer / 站点名
 *
 * 可选打包:目录生成后调用系统 tar(`tar -czf`)压成同名 .tar.gz;
 * tar 不可用或失败时优雅降级 —— 保留目录并提示,不影响备份本身。
 *
 * 保留策略:默认保留最近 14 份(BACKUP_KEEP 环境变量可覆盖),超出部分按名字序
 * (名字内嵌时间戳,字典序即时间序)删除,目录与同名 .tar.gz 均删。
 *
 * 零依赖;可在服务运行中执行(VACUUM INTO 只短暂持有读锁,配合 busy_timeout 等待)。
 */
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const KEEP = Math.max(1, Number(process.env.BACKUP_KEEP) || 14);
const PORT = Number(process.env.PORT) || 9000;

const p2 = (n) => String(n).padStart(2, '0');
const kb = (n) => `${(n / 1024).toFixed(1)} KB`;

const die = (msg) => { console.error(`备份失败:${msg}`); process.exit(1); };

if (!fs.existsSync(DATA_DIR)) die(`数据目录不存在:${DATA_DIR}`);
const srcDb = path.join(DATA_DIR, 'idp.sqlite');
if (!fs.existsSync(srcDb)) die(`未找到数据库文件 ${srcDb}(服务是否初始化过?)`);

/* 备份名内嵌时间戳;同秒重跑时追加 -2/-3 避免重名 */
const d = new Date();
const stamp = `${d.getFullYear()}${p2(d.getMonth() + 1)}${p2(d.getDate())}-${p2(d.getHours())}${p2(d.getMinutes())}${p2(d.getSeconds())}`;
const backupsDir = path.join(DATA_DIR, 'backups');
fs.mkdirSync(backupsDir, { recursive: true });
let name = `sakuraid-backup-${stamp}`;
for (let i = 2; fs.existsSync(path.join(backupsDir, name)); i++) name = `sakuraid-backup-${stamp}-${i}`;
const dest = path.join(backupsDir, name);
fs.mkdirSync(dest);

/* 1. VACUUM INTO 一致性快照:输出文件不能已存在,产物为单文件自包含库(无 WAL 依赖) */
const db = new DatabaseSync(srcDb);
db.exec('PRAGMA busy_timeout = 5000');
db.exec(`VACUUM INTO '${path.join(dest, 'idp.sqlite').replaceAll("'", "''")}'`);
const dbSize = fs.statSync(path.join(dest, 'idp.sqlite')).size;

/* 顺带读 settings 表取 issuer / 站点名(runtime 合并逻辑:env BASE_URL 优先,默认本地端口) */
let issuer = process.env.BASE_URL || `http://localhost:${PORT}`;
let siteName = '樱落统一认证';
try {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'issuer'").get();
  if (row?.value) issuer = String(row.value).replace(/\/+$/, '');
  const sn = db.prepare("SELECT value FROM settings WHERE key = 'site_name'").get();
  if (sn?.value) siteName = String(sn.value);
} catch { /* 空库/无 settings 表时用默认值 */ }
db.close();

/* 2. uploads/ 整目录复制(不存在则跳过) */
const uploadsSrc = path.join(DATA_DIR, 'uploads');
let uploadCount = 0;
if (fs.existsSync(uploadsSrc)) {
  const copyDir = (src, dst) => {
    fs.mkdirSync(dst, { recursive: true });
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
      const s = path.join(src, entry.name), t = path.join(dst, entry.name);
      if (entry.isDirectory()) copyDir(s, t);
      else { fs.copyFileSync(s, t); uploadCount++; }
    }
  };
  copyDir(uploadsSrc, path.join(dest, 'uploads'));
}

/* 3. meta.txt:备份时间 / 版本 / issuer / 站点名 */
const version = (() => {
  try { return JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version || 'unknown'; }
  catch { return 'unknown'; }
})();
fs.writeFileSync(path.join(dest, 'meta.txt'), [
  'Sakura-Auth-Server 备份',
  `备份时间:${d.toISOString()}(本地 ${d.toLocaleString('zh-CN', { hour12: false })})`,
  `版本:${version}`,
  `Issuer:${issuer}`,
  `站点名:${siteName}`,
  `数据库:idp.sqlite(VACUUM INTO 一致性快照,${kb(dbSize)})`,
  `uploads:${uploadCount} 个文件`,
  '',
].join('\n'));

/* 4. 可选打包:系统 tar 压成同名 .tar.gz;失败/不可用时保留目录并提示(优雅降级) */
let tarNote;
const tarPath = path.join(backupsDir, `${name}.tar.gz`);
try {
  try {
    execFileSync('tar', ['-czf', tarPath, '-C', backupsDir, name], { stdio: 'pipe' });
  } catch {
    // GNU tar 会把含盘符的 Windows 路径当远程主机名,追加 --force-local 重试(Windows 自带 bsdtar 无此问题)
    execFileSync('tar', ['--force-local', '-czf', tarPath, '-C', backupsDir, name], { stdio: 'pipe' });
  }
  tarNote = `压缩包:${tarPath}(${kb(fs.statSync(tarPath).size)})`;
} catch (err) {
  try { fs.rmSync(tarPath, { force: true }); } catch { /* 清理半成品 */ }
  tarNote = '压缩包:未生成(系统 tar 不可用或打包失败,已保留完整备份目录)';
}

/* 5. 保留最近 KEEP 份:按名字倒序保留,超出的目录与同名 .tar.gz 一并删除 */
const BASE_RE = /^sakuraid-backup-\d{8}-\d{6}(-\d+)?$/;
const names = fs.readdirSync(backupsDir)
  .filter((n) => BASE_RE.test(n))
  .sort()
  .reverse();
let pruned = 0;
for (const stale of names.slice(KEEP)) {
  fs.rmSync(path.join(backupsDir, stale), { recursive: true, force: true });
  fs.rmSync(path.join(backupsDir, `${stale}.tar.gz`), { force: true });
  pruned++;
}

console.log(`备份完成:${dest}`);
console.log(`  数据库快照:idp.sqlite(${kb(dbSize)},VACUUM INTO)`);
console.log(`  uploads:${uploadCount} 个文件`);
console.log(`  ${tarNote}`);
console.log(`  保留:${Math.min(names.length, KEEP)} 份(策略:最近 ${KEEP} 份${pruned ? `,本次清理 ${pruned} 份` : ''})`);
