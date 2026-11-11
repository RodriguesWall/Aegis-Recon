# Multi-stage build of the React dashboard: Vite build, then nginx serves the
# static bundle and reverse-proxies /api to the aegisd container.
FROM node:22 AS build
WORKDIR /app
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM nginx:alpine
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
