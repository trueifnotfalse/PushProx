FROM golang:1.18.2-alpine3.15 as builder

ENV GO111MODULE=on

WORKDIR /app

COPY . .

RUN go mod download && \
    cd cmd/proxy && \
    go build -o ../../pushprox-proxy .

FROM alpine:3.15
ENV TZ=UTC

WORKDIR /app

COPY --from=builder /app/pushprox-proxy /app/pushprox-proxy
RUN chmod +x /app/pushprox-proxy

CMD ["/app/pushprox-proxy"]
