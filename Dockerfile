FROM node:20-alpine
WORKDIR /app
COPY package.json index.mjs local_engine.mjs mcp-config.json glama.json server.json smithery.yaml README.md LICENSE ./
USER node
ENTRYPOINT ["node", "./index.mjs"]
