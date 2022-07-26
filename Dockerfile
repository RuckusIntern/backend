FROM golang:1.18.1-alpine as builder
# Define build env
ENV GOOS linux
ENV CGO_ENABLED 0
# Add a work directory
WORKDIR /backend
# Cache and install dependencies
COPY go.mod go.sum ./
RUN go mod download
# Copy app files
COPY . .
# Build app
RUN apk add git
RUN go build -o backend

FROM alpine:3.14 as production
# Add certificates
RUN apk add --no-cache ca-certificates
# Copy built binary from builder
COPY --from=builder backend .
# Expose port
EXPOSE 7000
# Exec built binary
CMD ./backend