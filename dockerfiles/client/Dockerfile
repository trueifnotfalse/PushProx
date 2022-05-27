FROM golang:1.18.2-alpine3.15 as builder

ENV GO111MODULE=on

WORKDIR /app

COPY . .

RUN go mod download && go build -o ./pushprox-client cmd/client/main.go


FROM alpine:3.15
ENV TZ=UTC

WORKDIR /app

COPY --from=builder /app/pushprox-client /app/pushprox-client
RUN chmod +x /app/pushprox-client

CMD ["/app/pushprox-client"]
