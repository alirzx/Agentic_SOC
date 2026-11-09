FROM node:20-alpine AS builder
ARG NPM_CONFIG_REGISTRY=https://package-mirror.liara.ir/repository/npm/
ENV NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

FROM node:20-alpine
ARG NPM_CONFIG_REGISTRY=https://package-mirror.liara.ir/repository/npm/
ENV NPM_CONFIG_REGISTRY=${NPM_CONFIG_REGISTRY}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY --from=builder /app/dist ./dist
EXPOSE 8086
CMD ["node", "dist/index.js"]
