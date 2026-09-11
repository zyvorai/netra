# syntax=docker/dockerfile:1
FROM node:22-alpine AS web
WORKDIR /src
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
COPY --from=web /src/dist ./web/dist
RUN CGO_ENABLED=0 go build -o /out/netrad ./cmd/netrad \
 && CGO_ENABLED=0 go build -o /out/netractl ./cmd/netractl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/netrad /usr/local/bin/netrad
COPY --from=build /out/netractl /usr/local/bin/netractl
COPY --from=build /src/web/dist /usr/share/netra/web
ENV NETRA_WEB_DIR=/usr/share/netra/web
ENV NETRA_LISTEN=:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/netrad"]
