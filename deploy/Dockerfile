# syntax=docker/dockerfile:1.7
# Node 22, the same major CI and the release build the bundle with, so an
# image built from source embeds the same console as the released binary.
FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --ignore-scripts --no-fund --no-audit
COPY web/ ./
RUN npm run build

# The official golang image sets GOTOOLCHAIN=local, so the Go version here is
# the one this digest ships, NOT go.mod's toolchain line. Pin the digest to the
# Go release you want (currently 1.27.3) or the from-source build and image scan
# fall behind the toolchain line.
FROM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
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
