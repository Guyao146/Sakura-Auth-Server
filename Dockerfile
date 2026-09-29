# 轻量运行时镜像:零 npm 依赖,拷贝即用
FROM node:24-alpine

ENV NODE_ENV=production
ENV DATA_DIR=/data
ENV PORT=9000

WORKDIR /app
COPY package.json server.js ./
COPY src ./src

RUN mkdir -p /data
VOLUME /data
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:9000/healthz >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
