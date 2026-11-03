# MinIO's own images have been removed from Docker Hub, so the runtime image is
# built on Chainguard's wolfi-base. coreutils provides the GNU chroot --userspec
# used by docker-entrypoint.sh and the GNU head/tail options used by the tests;
# mc (from Wolfi) is what the compose healthchecks run ("mc ready local"); and
# bash is installed as /bin/sh because, as on the previous base, the tests drive
# the containers with "/bin/sh -c" scripts that rely on brace expansion.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:fd50bd0cdeb808cf4f45c9c9189e0cc7f7fcc27195d69abd6622c80527e7e021
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
