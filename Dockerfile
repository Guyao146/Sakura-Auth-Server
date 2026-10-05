# 轻量运行时镜像:零 npm 依赖,拷贝即用
FROM node:24-alpine

# OCI 标准标签:便于镜像仓库展示与来源追溯
LABEL org.opencontainers.image.title="Sakura-Auth-Server" \
      org.opencontainers.image.description="类 authentik 的轻量 OAuth2 / OpenID Connect 认证服务(零 npm 依赖)" \
      org.opencontainers.image.source="https://github.com/Guyao146/Sakura-Auth-Server" \
      org.opencontainers.image.licenses="Sakura-License-1.2" \
      org.opencontainers.image.vendor="Sakura Eco" \
      org.opencontainers.image.base.name="docker.io/library/node:24-alpine"

ENV NODE_ENV=production
ENV DATA_DIR=/data
ENV PORT=9000

WORKDIR /app
COPY package.json server.js LICENSE ./
COPY src ./src

# 数据目录归属官方镜像自带的 node 用户(uid 1000),服务以非 root 运行
RUN mkdir -p /data \
 && chown -R node:node /data

VOLUME /data
EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:9000/healthz >/dev/null 2>&1 || exit 1

USER node
CMD ["node", "server.js"]
