# MinIO's own images have been removed from Docker Hub, so the runtime image is
# built on Chainguard's wolfi-base. coreutils provides the GNU chroot --userspec
# used by docker-entrypoint.sh and the GNU head/tail options used by the tests;
# mc (from Wolfi) is what the compose healthchecks run ("mc ready local"); and
# bash is installed as /bin/sh because, as on the previous base, the tests drive
# the containers with "/bin/sh -c" scripts that rely on brace expansion.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:1d95114038f76513a9ace6fca107d5582b08c65981f81f61cb56bf7fd2ef216d
RUN apk add --no-cache bash coreutils ca-certificates-bundle mc && \
    ln -sf /bin/bash /bin/sh

# This Dockerfile is only used by "make docker", which packages the binary that
# "make build" has just written to ./minio (the upgrade and mint tests use the
# resulting image). It used to expect signed release artefacts named
# minio-<arch>.<RELEASE>, which nothing in this repository produces; release
# images are built elsewhere.
RUN chmod -R 777 /usr/bin

COPY ./minio /usr/bin/minio

COPY dockerscripts/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

VOLUME ["/data"]

CMD ["minio"]
