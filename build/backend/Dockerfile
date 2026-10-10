# Build stage
FROM golang:alpine AS builder

WORKDIR /app
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /mirage ./cmd/mirage

# Runtime
FROM alpine:3.19
WORKDIR /app
# docker-cli is required because this process applies host firewall rules by
# running the firewall helper image through the mounted Docker socket.
# iptables inside this container would not change the Docker host.
RUN apk add --no-cache \
    ca-certificates \
    docker-cli \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ttf-freefont \
    libstdc++
ENV CHROME_PATH=/usr/bin/chromium-browser
COPY --from=builder /mirage /app/mirage
COPY prompts.yaml /app/prompts.yaml
EXPOSE 8443
ENTRYPOINT ["/app/mirage"]
