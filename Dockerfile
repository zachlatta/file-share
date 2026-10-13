# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/file-share ./cmd/file-share

FROM alpine:3.22
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 app
COPY --from=build /out/file-share /usr/local/bin/file-share
USER app
ENV ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["file-share"]
CMD ["serve"]
