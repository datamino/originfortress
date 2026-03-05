FROM node:22-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts 2>/dev/null || npm install --omit=dev --ignore-scripts
COPY . .

# Minimal image — just Origin Fortress CLI
ENTRYPOINT ["node", "bin/origin-fortress.js"]
CMD ["--help"]
