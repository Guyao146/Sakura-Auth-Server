import { escapeHtml as esc } from '../core/util.js';
import { SCOPES } from '../core/config.js';

/** scope id 列表 → 带中文描述的展示项 */
export const scopeItems = (scopeList) =>
  scopeList.map((id) => ({ id, desc: SCOPES[id] || id }));

export const banner = (msg, type = '') =>
  msg ? `<div class="banner ${type}">${msg}</div>` : '';

export const badge = (text, cls = '') => `<span class="badge ${cls}">${esc(text)}</span>`;

export function hiddenInputs(obj) {
  return Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('\n');
}

/** scope 列表:mode=plain(同意页)/ checkbox(管理端表单) */
export function scopeList(items, { mode = 'plain', name = 'scopes' } = {}) {
  return items.map((it) => {
    if (mode === 'checkbox') {
      return `<label class="checkline"><input type="checkbox" name="${name}" value="${esc(it.id)}"${it.checked ? ' checked' : ''}>
        <span><code>${esc(it.id)}</code><span class="muted">${esc(it.desc)}</span></span></label>`;
    }
    return `<div class="scope-item"><code>${esc(it.id)}</code><span class="desc">${esc(it.desc)}</span></div>`;
  }).join('\n');
}

export const kvRow = (label, value) => `<div class="kv"><b>${esc(label)}</b><span>${value}</span></div>`;

export const statCard = (value, label) => `<div class="stat"><b>${esc(value)}</b><span>${esc(label)}</span></div>`;

/** 向导步骤指示器 */
export function stepIndicator(current, total = 4, labels = ['环境检测', '站点设置', '管理员账号', '完成']) {
  return `<div class="steps">${labels.map((l, i) => {
    const n = i + 1;
    const cls = n < current ? 'step done' : n === current ? 'step on' : 'step';
    return `<div class="${cls}">${n}. ${esc(l)}</div>`;
  }).join('')}</div>`;
}
