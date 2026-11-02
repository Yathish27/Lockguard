# Cloud Run service: the Lockguard API (hosted mode). Chromium ships with the Playwright base image.
FROM mcr.microsoft.com/playwright:v1.64.1-noble

WORKDIR /app

# Install deps against the lockfile (no lifecycle scripts; the base image already has the browser).
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/package.json
COPY packages/server/package.json packages/server/package.json
COPY packages/lab/package.json packages/lab/package.json
COPY packages/ui/package.json packages/ui/package.json
RUN npm ci --ignore-scripts

# Build everything (core, server, lab, ui).
COPY . .
RUN npm run build

ENV NODE_ENV=production
ENV LOCKGUARD_HOSTED=1
# Cloud Run provides PORT; the CLI honours it. Default for local docker run:
ENV PORT=8080
EXPOSE 8080

# Run the API (also serves the built UI; Firebase Hosting serves static and proxies /api here).
CMD ["node", "packages/server/dist/cli.js", "ui", "--host", "0.0.0.0", "--no-open"]
