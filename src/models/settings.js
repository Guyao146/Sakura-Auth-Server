import { getDb } from '../core/db.js';

export function all() {
  return getDb().prepare('SELECT key, value FROM settings').all();
}

export function getMap() {
  return Object.fromEntries(all().map((r) => [r.key, r.value]));
}

export function getSetting(key) {
  const row = getDb().prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

export function setSetting(key, value) {
  getDb().prepare(
    'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
  ).run(key, String(value));
}
