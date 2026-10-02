/**
 * multipart/form-data 二进制安全解析(零依赖)与 Logo 上传目录管理。
 * 用法约束:server.js 管线对 multipart 请求跳过文本 readBody(保持 req 为未消费的可读流),
 * 由上传类 handler 内部调用 parseMultipart 直接读取原始字节,避免文本化破坏二进制内容。
 */
import fs from 'node:fs';
import path from 'node:path';
import { config } from './config.js';

/** 上传文件(Logo)存放目录:{DATA_DIR}/uploads */
export const uploadsDir = () => path.join(config.dataDir, 'uploads');

/** 启动时/写文件前确保上传目录存在,返回目录路径 */
export function ensureUploadsDir() {
  fs.mkdirSync(uploadsDir(), { recursive: true });
  return uploadsDir();
}

/** 上传文件名严格白名单(仅本服务生成的 <clientId>.<ext> 形态,防目录穿越) */
export const UPLOAD_FILE_RE = /^([a-zA-Z0-9_-]+)\.(png|jpg|jpeg|webp|gif)$/;

const CONTENT_TYPES = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  gif: 'image/gif',
};

export const uploadContentType = (ext) => CONTENT_TYPES[ext] || 'application/octet-stream';

/**
 * 按文件头魔数嗅探图片类型(不信扩展名与声明的 Content-Type)。
 * PNG 89 50 4E 47;JPEG FF D8 FF;WebP "RIFF....WEBP";GIF "GIF"(GIF87a/89a)。
 * 返回规范扩展名(png/jpg/webp/gif)或 null(非支持的图片类型)。
 */
export function sniffImageExt(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 3) return null;
  const ascii = (off, len) => buf.slice(off, off + len).toString('latin1');
  if (ascii(0, 4) === '\x89PNG') return 'png';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpg';
  if (buf.length >= 12 && ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') return 'webp';
  if (ascii(0, 3) === 'GIF') return 'gif';
  return null;
}

const statusError = (status, message) => Object.assign(new Error(message), { status });

/**
 * 解析 multipart/form-data 请求体。
 * 返回 Promise<{ fields: Record<string,string>, files: Record<string,{filename,contentType,data:Buffer}> }>;
 * 文本字段取 UTF-8,文件段保留原始字节。
 * - 非 multipart / 缺 boundary / 报文残缺 → 抛 { status: 400 }
 * - 超过 maxSize(默认 2MB)→ 排空请求流后抛 { status: 413 }(管线统一渲染 413 页)
 */
export async function parseMultipart(req, { maxSize = 2 * 1024 * 1024 } = {}) {
  const contentType = String(req.headers['content-type'] || '');
  if (!contentType.toLowerCase().includes('multipart/form-data')) {
    throw statusError(400, '请求不是 multipart/form-data');
  }
  const bm = contentType.match(/boundary=(?:"([^"]+)"|([^;,\s]+))/i);
  if (!bm) throw statusError(400, 'multipart 请求缺少 boundary');
  const boundary = '--' + (bm[1] || bm[2]);

  // 累积原始字节(二进制安全);超限后不再缓存、继续把流读完,保证客户端能收到 413 响应
  const chunks = [];
  let size = 0;
  let tooLarge = false;
  await new Promise((resolve, reject) => {
    req.on('data', (ch) => {
      size += ch.length;
      if (size > maxSize) { tooLarge = true; chunks.length = 0; return; }
      chunks.push(ch);
    });
    req.on('end', resolve);
    req.on('error', reject);
  });
  if (tooLarge) throw statusError(413, '上传内容超过大小限制');
  const body = Buffer.concat(chunks);

  const fields = {};
  const files = {};
  const bBoundary = Buffer.from(boundary);
  let pos = body.indexOf(bBoundary);
  if (pos === -1) throw statusError(400, 'multipart 报文不完整(缺少起始边界)');
  pos += bBoundary.length;

  for (;;) {
    // 结束分隔符:--boundary--
    if (body[pos] === 0x2d && body[pos + 1] === 0x2d) break;
    // 普通分隔符后应为 CRLF(兼容裸 LF)
    if (body[pos] === 0x0d && body[pos + 1] === 0x0a) pos += 2;
    else if (body[pos] === 0x0a) pos += 1;
    const headerEnd = body.indexOf('\r\n\r\n', pos);
    if (headerEnd === -1) throw statusError(400, 'multipart 分段头部不完整');
    const headerBlock = body.slice(pos, headerEnd).toString('utf8');
    const dataStart = headerEnd + 4;
    const sep = Buffer.from('\r\n' + boundary);
    const next = body.indexOf(sep, dataStart);
    if (next === -1) throw statusError(400, 'multipart 分段不完整(缺少结束边界)');
    const data = body.slice(dataStart, next);
    pos = next + sep.length;

    const headers = {};
    for (const line of headerBlock.split('\r\n')) {
      const i = line.indexOf(':');
      if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
    }
    const disp = headers['content-disposition'] || '';
    const nameM = disp.match(/\bname="([^"]*)"/i);
    if (!nameM) continue; // 无字段名的段(如多余的 Preamble)忽略
    const fieldName = nameM[1];
    if (/\bfilename="/i.test(disp)) {
      // 文件段:filename 可为空串(未选文件),仍按文件处理
      const fileM = disp.match(/\bfilename="([^"]*)"/i);
      files[fieldName] = { filename: fileM[1], contentType: headers['content-type'] || '', data };
    } else {
      fields[fieldName] = data.toString('utf8');
    }
  }
  return { fields, files };
}
