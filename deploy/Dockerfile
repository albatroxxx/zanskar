# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-fund --no-audit
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -tags webui \
      -ldflags "-s -w -X github.com/albatroxxx/zanskar/internal/version.Version=${VERSION}" \
      -o /out/zanskar ./cmd/zanskar

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/zanskar /zanskar
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/zanskar"]
CMD ["serve"]
