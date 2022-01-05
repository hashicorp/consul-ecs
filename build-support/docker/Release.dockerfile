# This Dockerfile creates a production release image for the project. This
# downloads the release from releases.hashicorp.com and therefore requires that
# the release is published before building the Docker image.
#
# We don't rebuild the software because we want the exact checksums and
# binary signatures to match the software and our builds aren't fully
# reproducible currently.

FROM alpine:3.13

# NAME and VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=consul VERSION=1.2.3.
ARG NAME=consul-ecs
ARG VERSION

LABEL name=$NAME \
      org.opencontainers.image.title=$NAME \
      maintainer="Consul Team <consul@hashicorp.com>" \
      org.opencontainers.image.authors="Consul Team <consul@hashicorp.com>" \
      vendor="HashiCorp" \
      org.opencontainers.image.vendor="HashiCorp" \
      version=$VERSION \
      org.opencontainers.image.version=$VERSION \
      release=$VERSION \
      summary="consul-ecs provides first-class integration between Consul and AWS ECS." \
      description="consul-ecs provides first-class integration between Consul and AWS ECS." \
      org.opencontainers.image.description="consul-ecs provides first-class integration between Consul and AWS ECS." \
      org.opencontainers.image.url="https://www.consul.io/" \
      org.opencontainers.image.documentation="https://www.consul.io/docs/ecs" \
      org.opencontainers.image.source="https://github.com/hashicorp/consul-ecs"

# This is the location of the releases.
ENV HASHICORP_RELEASES=https://releases.hashicorp.com

# Create a non-root user to run the software.
RUN addgroup ${NAME} && \
    adduser -S -G ${NAME} ${NAME} && \
    # Changing the owner of /consul to NAME allows mesh-init to run as NAME rather
    # than root. See
    # https://docs.aws.amazon.com/AmazonECS/latest/developerguide/bind-mounts.html
    # for more information
    mkdir /consul && \
    chown ${NAME}:${NAME} /consul

# This folder will hold the consul binary that comes from the the Consul client
# container at runtime
ENV PATH="/bin/consul-inject:${PATH}"


VOLUME [ "/consul" ]

# Set up certificates, base tools, and software.
RUN set -eux && \
    apk add --no-cache ca-certificates curl gnupg libcap openssl su-exec iputils iptables && \
    BUILD_GPGKEY=C874011F0AB405110D02105534365D9472D7468F; \
    found=''; \
    for server in \
        hkp://p80.pool.sks-keyservers.net:80 \
        hkp://keyserver.ubuntu.com:80 \
        hkp://pgp.mit.edu:80 \
    ; do \
        echo "Fetching GPG key $BUILD_GPGKEY from $server"; \
        gpg --keyserver "$server" --recv-keys "$BUILD_GPGKEY" && found=yes && break; \
    done; \
    test -z "$found" && echo >&2 "error: failed to fetch GPG key $BUILD_GPGKEY" && exit 1; \
    mkdir -p /tmp/build && \
    cd /tmp/build && \
    apkArch="$(apk --print-arch)" && \
    case "${apkArch}" in \
        aarch64) ARCH='arm64' ;; \
        armhf) ARCH='arm' ;; \
        x86) ARCH='386' ;; \
        x86_64) ARCH='amd64' ;; \
        *) echo >&2 "error: unsupported architecture: ${apkArch} (see ${HASHICORP_RELEASES}/${NAME}/${VERSION}/)" && exit 1 ;; \
    esac && \
    wget ${HASHICORP_RELEASES}/${NAME}/${VERSION}/${NAME}_${VERSION}_linux_${ARCH}.zip && \
    wget ${HASHICORP_RELEASES}/${NAME}/${VERSION}/${NAME}_${VERSION}_SHA256SUMS && \
    wget ${HASHICORP_RELEASES}/${NAME}/${VERSION}/${NAME}_${VERSION}_SHA256SUMS.sig && \
    gpg --batch --verify ${NAME}_${VERSION}_SHA256SUMS.sig ${NAME}_${VERSION}_SHA256SUMS && \
    grep ${NAME}_${VERSION}_linux_${ARCH}.zip ${NAME}_${VERSION}_SHA256SUMS | sha256sum -c && \
    unzip -d /bin ${NAME}_${VERSION}_linux_${ARCH}.zip && \
    cd /tmp && \
    rm -rf /tmp/build && \
    apk del gnupg openssl && \
    rm -rf /root/.gnupg

USER ${NAME}
ENTRYPOINT ["/bin/consul-ecs"]
