import { escapeHtml as esc } from '../core/util.js';
import { SCOPES } from '../core/config.js';

/** scope id 列表 → 带中文描述的展示项 */
export const scopeItems = (scopeList) =>
  scopeList.map((id) => ({ id, desc: SCOPES[id] || id }));

export const banner = (msg, type = '') =>
  msg ? `<div class="banner ${type}" role="${type === 'err' ? 'alert' : 'status'}">${msg}</div>` : '';

export const badge = (text, cls = '') => `<span class="badge ${cls}">${esc(text)}</span>`;

export function hiddenInputs(obj) {
  return Object.entries(obj)
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('\n');
}

/** scope 的中文短名与线性图标(同意授权页用) */
export const SCOPE_NAMES = {
  openid: '登录身份',
  profile: '基本资料',
  email: '邮箱地址',
  groups: '用户组',
  offline_access: '离线访问',
};

const SCOPE_ICONS = {
  openid: '<rect x="1.75" y="3" width="12.5" height="10" rx="2"/><circle cx="5.4" cy="8" r="1.7"/><path d="M8.6 6.6h3.6M8.6 9.4h3.6"/>',
  profile: '<circle cx="8" cy="5.4" r="2.6"/><path d="M2.9 13.6c.5-2.7 2.6-4.1 5.1-4.1s4.6 1.4 5.1 4.1"/>',
  email: '<rect x="1.75" y="3" width="12.5" height="10" rx="2"/><path d="M2.5 4.5 8 8.6l5.5-4.1"/>',
  groups: '<circle cx="5.4" cy="6" r="2.3"/><circle cx="10.9" cy="6.6" r="1.9"/><path d="M2.2 13.4c.4-2.4 2.2-3.6 4.4-3.6M9 13.4c.3-1.9 1.7-2.9 3.4-2.9"/>',
  offline_access: '<path d="M13.4 8A5.4 5.4 0 1 1 11.8 4.1"/><path d="M13.6 1.8v3h-3"/>',
  default: '<path d="M8 1.8l1.3 4.9L14.2 8l-4.9 1.3L8 14.2 6.7 9.3 1.8 8l4.9-1.3z"/>',
};

/** 内联 SVG 图标(随主题 currentColor,零外部资源) */
export const scopeIcon = (id) =>
  `<svg viewBox="0 0 16 16" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${SCOPE_ICONS[id] || SCOPE_ICONS.default}</svg>`;

/** 管理端表单的 scope 复选框列表 */
export function scopeList(items, { name = 'scopes' } = {}) {
  return items.map((it) =>
    `<label class="checkline"><input type="checkbox" name="${name}" value="${esc(it.id)}"${it.checked ? ' checked' : ''}>
      <span><code>${esc(it.id)}</code><span class="muted">${esc(it.desc)}</span></span></label>`).join('\n');
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
