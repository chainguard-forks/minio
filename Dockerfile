FROM minio/minio:latest@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e

ARG TARGETARCH
ARG RELEASE

RUN chmod -R 777 /usr/bin

COPY ./minio-${TARGETARCH}.${RELEASE} /usr/bin/minio
COPY ./minio-${TARGETARCH}.${RELEASE}.minisig /usr/bin/minio.minisig
COPY ./minio-${TARGETARCH}.${RELEASE}.sha256sum /usr/bin/minio.sha256sum

COPY dockerscripts/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

VOLUME ["/data"]

CMD ["minio"]
