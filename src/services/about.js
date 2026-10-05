/** 「关于我们」公开页 + 管理端内容配置:内容存 settings 表,纯文本转义渲染(无 HTML 注入面)。 */
import { sendHtml, redirect } from '../core/http.js';
import { getRuntime, updateRuntime } from '../core/runtime.js';
import * as settingsApi from '../models/settings.js';
import { escapeHtml as esc } from '../core/util.js';
import { hiddenInputs } from '../views/components.js';
import { authPage, adminPage } from '../views/layout.js';
import { t, currentLang } from '../core/i18n.js';
import { record } from './audit.js';

const MAX_TITLE = 60, MAX_CONTENT = 5000;

/** 纯文本 → HTML:先转义,再保留换行/段落(空行分段) */
function renderContent(text) {
  return esc(text)
    .replace(/\r?\n[ \t]*\r?\n/g, '</p><p>')
    .replace(/\r?\n/g, '<br>');
}

/** GET /about —— 公开页(匿名可访问,未配置内容时给占位说明) */
export function showAbout(ctx) {
  const rt = getRuntime();
  const about = rt.about;
  const L = currentLang();
  const body = about.content
    ? `<p>${renderContent(about.content)}</p>`
    : `<p class="muted">${esc(t(L, 'about.empty'))}</p>`;
  sendHtml(ctx.res, 200, authPage({
    theme: ctx.theme, siteName: rt.siteName, footer: false,
    title: `${about.title} · ${rt.siteName}`,
    content: `<h3 style="margin-top:0">${esc(about.title)}</h3>${body}`,
  }));
}

/** GET /admin/about —— 内容编辑表单 */
export function showAboutSettings(ctx, { err = ctx.query.get('err'), msg = ctx.query.get('msg'), values } = {}) {
  const rt = getRuntime();
  const about = values || rt.about;
  const notice = msg ? `<div class="banner ok">${esc(msg)}</div>`
    : err ? `<div class="banner err">${esc(err)}</div>` : '';
  sendHtml(ctx.res, 200, adminPage({
    theme: ctx.theme, siteName: rt.siteName, user: ctx.user, cur: '/admin/about',
    title: '关于我们 · 管理控制台', content: `
    <h2>关于我们</h2>
    ${notice}
    <p class="small">显示在公开页 <a href="/about">/about</a>;填写内容后,全站页脚出现「关于本站」入口。正文为纯文本,换行保留,HTML 标签会被转义后原样显示。</p>
    <form method="post" action="/admin/about">
      ${hiddenInputs({ _csrf: ctx.session.csrf })}
      <label>标题(≤ ${MAX_TITLE} 字)</label>
      <input name="title" value="${esc(about.title)}" maxlength="${MAX_TITLE}" required>
      <label>正文(≤ ${MAX_CONTENT} 字,空行分段)</label>
      <textarea name="content" rows="12" maxlength="${MAX_CONTENT}">${esc(about.content)}</textarea>
      <button class="btn btn-primary">保存</button>
    </form>`,
  }));
}

/** POST /admin/about —— 保存内容(标题必填、长度限制;CSRF 双提交) */
export function saveAbout(ctx) {
  const b = ctx.body || {};
  if (b._csrf !== ctx.session.csrf) {
    return redirect(ctx.res, '/admin/about?err=' + encodeURIComponent('页面已过期,请重试。'));
  }
  const title = typeof b.title === 'string' ? b.title.trim() : '';
  const content = typeof b.content === 'string' ? b.content.trim() : '';
  if (title.length > MAX_TITLE || content.length > MAX_CONTENT) {
    return showAboutSettings(ctx, { err: '标题或正文超出长度限制,未保存。', values: { title, content } });
  }
  if (!title) {
    return redirect(ctx.res, '/admin/about?err=' + encodeURIComponent('标题不能为空。'));
  }
  updateRuntime({ about_title: title, about_content: content }, settingsApi.setSetting);
  record(ctx, 'admin.about_updated', title);
  redirect(ctx.res, '/admin/about?msg=' + encodeURIComponent('「关于我们」内容已保存。'));
}
