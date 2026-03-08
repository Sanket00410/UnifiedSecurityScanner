FROM golang:1.26-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/uss-platform-services-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/uss-platform-services-worker ./cmd/worker

FROM alpine:3.22

RUN adduser -D -u 10001 uss && apk add --no-cache ca-certificates tzdata

COPY --from=build /out/uss-platform-services-api /usr/local/bin/uss-platform-services-api
COPY --from=build /out/uss-platform-services-worker /usr/local/bin/uss-platform-services-worker

USER uss
EXPOSE 18090

ENTRYPOINT ["/usr/local/bin/uss-platform-services-api"]
