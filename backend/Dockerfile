# ---- build stage ----
FROM golang:1.25-alpine AS build
WORKDIR /app

# RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# ВАЖНО: предполагаем, что main package у тебя в корне backend/ (main.go)
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/api/

# ---- runtime stage ----
FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata

COPY --from=build /app/server /app/server

EXPOSE 8080
ENV LISTEN_ADDR=":8080"

CMD ["/app/server"]
