# Build stage
FROM golang:alpine AS builder

WORKDIR /app

# Copy go mod files from root
COPY ../../go.mod ../../go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire project
COPY ../.. .

# Build the binary from the server directory
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mcp-server ./prototype-2/server

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/mcp-server .

# Run the binary
ENTRYPOINT ["./mcp-server"]