# --- build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build static-ish binary; trim symbols
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /out/webmks-proxy .

# --- runtime stage ---
FROM alpine:3.20
RUN addgroup -S app && adduser -S app -G app \
 && apk add --no-cache ca-certificates tzdata wget
WORKDIR /app
COPY --from=build /out/webmks-proxy /app/webmks-proxy
COPY templates/ /app/templates/
COPY static/ /app/static/
USER app
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://127.0.0.1:8081/ >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/app/webmks-proxy"]
CMD ["-listen", ":8081"]
