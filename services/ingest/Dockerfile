FROM golang:1.25-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates gcc musl-dev

# proxy.golang.org returns 403 in some regions; fall through to public mirrors.
# Override at build time: docker build --build-arg GOPROXY=https://goproxy.cn,direct
ARG GOPROXY=https://proxy.golang.org,https://goproxy.io,https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.org
ENV GOPROXY=${GOPROXY} \
    GOSUMDB=${GOSUMDB} \
    GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o /ingest-service ./main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /ingest-service .

EXPOSE 8080

CMD ["./ingest-service"]
