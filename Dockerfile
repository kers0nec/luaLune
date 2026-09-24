FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN apk add --no-cache git && npm install --omit=dev --no-audit --no-fund
COPY . .
RUN rm -rf vendor/prometheus && git clone --depth 1 https://github.com/prometheus-lua/Prometheus.git vendor/prometheus
ENV NODE_ENV=production
EXPOSE 10000
CMD ["npm","start"]