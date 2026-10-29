
FROM golang:1.25-alpine AS build

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /ruangkita-backend .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 appuser

WORKDIR /app

COPY --from=build /ruangkita-backend /app/ruangkita-backend

USER appuser

EXPOSE 8088

ENTRYPOINT ["/app/ruangkita-backend"]
