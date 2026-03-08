FROM golang:1.26-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates tzdata

COPY control-plane ./control-plane
COPY risk-engine ./risk-engine

WORKDIR /src/risk-engine
RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/uss-risk-engine-api ./cmd/api

FROM alpine:3.22

RUN adduser -D -u 10001 uss && apk add --no-cache ca-certificates tzdata

COPY --from=build /out/uss-risk-engine-api /usr/local/bin/uss-risk-engine-api

USER uss
EXPOSE 18110

ENTRYPOINT ["/usr/local/bin/uss-risk-engine-api"]
