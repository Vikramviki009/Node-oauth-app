# Stage 1: Build Typescript
FROM node:lts-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY  src/ ./src/
RUN npm run build

# Stage 2: Production Runner
FROM node:lts-alpine as runner
WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/dist ./dist

# Security: run as unpriviliged user
USER node

EXPOSE 5000

CMD [ "node", "dist/server.js" ]