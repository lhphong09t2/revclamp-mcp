FROM node:22-alpine@sha256:f8dc659272b88820263b060081c67c160a1f74f987113b8682623c1b0c015316

WORKDIR /app

ENV NODE_ENV=production

COPY --chown=node:node package.json index.mjs actor_config.json server.json glama.json README.md ./
COPY --chown=node:node src ./src
COPY --chown=node:node assets ./assets
COPY --chown=node:node .actor ./.actor
COPY --chown=node:node .well-known ./.well-known

USER node

ENTRYPOINT ["node", "./index.mjs"]
