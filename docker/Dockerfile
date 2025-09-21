FROM golang:1.24-alpine AS builder

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/

RUN go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o reticulum-go \
    ./cmd/reticulum-go

FROM busybox:latest

RUN adduser -D -s /bin/sh app

COPY --from=builder /build/reticulum-go /usr/local/bin/reticulum-go

RUN chmod +x /usr/local/bin/reticulum-go
RUN mkdir -p /app && chown app:app /app

USER app
WORKDIR /app

EXPOSE 4242

ENTRYPOINT ["/usr/local/bin/reticulum-go"]
