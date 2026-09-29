/** 极简结构化日志:时间 级别 消息(附加字段 JSON) */

function line(level, msg, extra) {
  const ts = new Date().toISOString();
  const tail = extra === undefined ? '' : ' ' + JSON.stringify(extra);
  console.log(`${ts} ${level} ${msg}${tail}`);
}

export const logger = {
  info: (msg, extra) => line('I', msg, extra),
  warn: (msg, extra) => line('W', msg, extra),
  error: (msg, extra) => line('E', msg, extra),
  request(method, path, status, ms) {
    line('I', `${method} ${path} ${status} ${ms}ms`);
  },
};
