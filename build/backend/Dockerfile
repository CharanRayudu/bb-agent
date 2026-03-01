# Build stage
FROM golang:alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /mirage ./cmd/mirage

# Runtime
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /mirage /mirage
EXPOSE 8443
ENTRYPOINT ["/mirage"]
