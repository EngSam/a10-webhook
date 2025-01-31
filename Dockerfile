# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o /app/webhook ./cmd/webhook.go

# Final stage
FROM alpine:3.21
COPY --from=builder /app/webhook /usr/local/bin/webhook

ENTRYPOINT ["/usr/local/bin/webhook"]