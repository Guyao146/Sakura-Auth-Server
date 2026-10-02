/** 应用健康探测:定期探测各应用配置的 health_url,内存快照供门户状态点与 /api/registry 读取。
 *  单实例设计:模块级定时器 import 即启动(unref,不阻止进程退出),启动 3 秒后先跑一轮。 */
import * as clients from '../models/clients.js';
import { logger } from '../core/logger.js';

const TIMEOUT_MS = 5000; // 单次探测超时
const INTERVAL_MS = 60_000; // 周期探测间隔
const START_DELAY_MS = 3_000; // 启动后首跑延迟

/** clientId → { status:'up'|'down'|'unknown', code, latencyMs, checkedAt } */
const snapshots = new Map();

const makeSnapshot = (status, { code = null, latencyMs = null } = {}) => ({
  status,
  code,
  latencyMs,
  checkedAt: new Date().toISOString(),
});

/** 探测单个应用:healthUrl 为空 → unknown;2xx → up(记延迟);非 2xx / 网络异常 → down。绝不抛出 */
export async function probeOne(client) {
  if (!client || !client.client_id) return null;
  const url = String(client.health_url ?? client.healthUrl ?? '').trim();
  if (!url) {
    const entry = makeSnapshot('unknown');
    snapshots.set(client.client_id, entry);
    return entry;
  }
  const started = Date.now();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
    const entry = makeSnapshot(res.ok ? 'up' : 'down', { code: res.status, latencyMs: Date.now() - started });
    snapshots.set(client.client_id, entry);
    return entry;
  } catch {
    const entry = makeSnapshot('down', { latencyMs: Date.now() - started });
    snapshots.set(client.client_id, entry);
    return entry;
  }
}

/** 探测全部应用(串行,单次 5s 超时),并清理已删除应用的快照条目。返回快照 Map。
 *  带运行守卫:应用多且大量离线时单轮可能超过 60s 间隔,防止轮次重叠堆积。 */
let probing = false;

export async function probeAll() {
  if (probing) return snapshots;
  probing = true;
  try {
    return await probeAllInner();
  } finally {
    probing = false;
  }
}

async function probeAllInner() {
  const apps = clients.list();
  const alive = new Set(apps.map((c) => c.client_id));
  for (const id of [...snapshots.keys()]) {
    if (!alive.has(id)) snapshots.delete(id);
  }
  for (const app of apps) await probeOne(app);
  return snapshots;
}

/** 读取单个应用的健康快照;无记录返回 null */
export const get = (clientId) => snapshots.get(clientId) || null;

/** 读取全部快照的副本 */
export const all = () => new Map(snapshots);

/** 应用保存后立即探测(fire-and-forget,失败静默,不阻塞响应) */
export const probeSoon = (client) => {
  if (client?.client_id) void probeOne(client).catch(() => {});
};

const tick = () => {
  probeAll().catch((e) => logger.error('应用健康探测失败', { err: e?.stack || String(e) }));
};
setInterval(tick, INTERVAL_MS).unref();
setTimeout(tick, START_DELAY_MS).unref();
