# --- build stage: install deps (build tools present for native modules) ------
FROM node:20-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci --omit=dev

# --- runtime stage ------------------------------------------------------------
FROM node:20-bookworm-slim
WORKDIR /app
# ffmpeg powers thumbnails, transcoding, and the perceptual hash.
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/node_modules ./node_modules
COPY . .
# Runtime data lives on a volume; create + own the dirs as the node user.
RUN mkdir -p data videos thumbs tmp && chown -R node:node /app
USER node
ENV PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
