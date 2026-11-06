FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914

WORKDIR /app

ENV NODE_ENV=production

COPY --chown=node:node package.json index.mjs actor_config.json server.json glama.json README.md ./
COPY --chown=node:node src ./src
COPY --chown=node:node assets ./assets
COPY --chown=node:node .actor ./.actor
COPY --chown=node:node .well-known ./.well-known

USER node

ENTRYPOINT ["node", "./index.mjs"]
