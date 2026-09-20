FROM golang:1.24-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git ca-certificates

ARG GOPROXY=https://proxy.golang.org,https://goproxy.io,https://goproxy.cn,direct
ARG GOSUMDB=sum.golang.org
ENV GOPROXY=${GOPROXY} \
    GOSUMDB=${GOSUMDB} \
    GOTOOLCHAIN=local

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /enrichment-service ./main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /enrichment-service .

EXPOSE 8082

CMD ["./enrichment-service"]
