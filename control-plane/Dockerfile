FROM golang:1.26-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/uss-control-plane-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/uss-control-plane-scheduler ./cmd/scheduler

FROM alpine:3.22

RUN adduser -D -u 10001 uss && apk add --no-cache ca-certificates tzdata

COPY --from=build /out/uss-control-plane-api /usr/local/bin/uss-control-plane-api
COPY --from=build /out/uss-control-plane-scheduler /usr/local/bin/uss-control-plane-scheduler

USER uss
EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/uss-control-plane-api"]
