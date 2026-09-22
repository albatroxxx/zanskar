# syntax=docker/dockerfile:1.7
FROM node:25-alpine AS web
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
# Stage the data directory so the final image carries it owned by the nonroot
# uid (65532); a fresh named volume mounted here then inherits that ownership.
RUN mkdir -p /var/lib/zanskar/recordings

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/zanskar /zanskar
# Distroless has no shell to chown at runtime, so pre-own the data dir here.
# When docker-compose.yml mounts an empty named volume at /var/lib/zanskar it
# inherits this ownership, letting the nonroot process write the SQLite database
# and recordings.
COPY --from=build --chown=65532:65532 /var/lib/zanskar /var/lib/zanskar
USER nonroot:nonroot
EXPOSE 8443
ENTRYPOINT ["/zanskar"]
CMD ["serve"]
