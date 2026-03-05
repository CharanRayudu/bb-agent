# Build stage
FROM golang:alpine AS builder

WORKDIR /app
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /mirage ./cmd/mirage

# Runtime
FROM alpine:3.19
WORKDIR /app
RUN apk add --no-cache \
    ca-certificates \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ttf-freefont \
    libstdc++
COPY --from=builder /mirage /app/mirage
COPY prompts.yaml /app/prompts.yaml
EXPOSE 8443
ENTRYPOINT ["/app/mirage"]
