FROM golang:1.26.3-alpine AS base
RUN apk add --no-cache git ca-certificates
WORKDIR /app

# Install Air for hot reload
FROM base AS dev
RUN go install github.com/air-verse/air@latest
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
EXPOSE 8080
CMD ["air", "-c", ".air.toml"]

# Build stage
FROM base AS builder
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/worker ./cmd/worker
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/migrate ./cmd/migrate

# Production
FROM alpine:3.19 AS production
RUN apk add --no-cache ca-certificates git
WORKDIR /app
COPY --from=builder /app/bin/api ./api
COPY --from=builder /app/bin/worker ./worker
COPY --from=builder /app/bin/migrate ./migrate
COPY --from=builder /app/internal/db/migrations ./internal/db/migrations
EXPOSE 8080
CMD ["./api"]
