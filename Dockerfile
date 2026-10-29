
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 \
    GOOS=${TARGETOS:-linux} \
    GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" \
    -o /ruangkita-backend .

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 appuser

WORKDIR /app

COPY --from=build /ruangkita-backend /app/ruangkita-backend

USER appuser

EXPOSE 8088

ENTRYPOINT ["/app/ruangkita-backend"]
