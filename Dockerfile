FROM alpine:latest as BUILDER
ARG NAME=consul-ecs
ARG VERSION

# This is the location of the releases.
ENV HASHICORP_RELEASES=https://releases.hashicorp.com

# Set up certificates, base tools, and software.
RUN set -eux && \
    apk add --no-cache ca-certificates curl gnupg libcap openssl su-exec iputils libc6-compat iptables && \
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
    armhf) ARCH='armhfv6' ;; \
    x86) ARCH='386' ;; \
    x86_64) ARCH='amd64' ;; \
    *) echo >&2 "error: unsupported architecture: ${apkArch} (see ${HASHICORP_RELEASES}/${NAME}/${VERSION}/)" && exit 1 ;; \
    esac && \
    wget ${HASHICORP_RELEASES}/${NAME}/${VERSION}/${NAME}_${VERSION}_linux_${ARCH}.zip && \
    wget ${HASHICORP_RELEASES}/${NAME}/${VERSION}/${NAME}_${VERSION}_SHA256SUMS && \
    wget ${HASHICORP_RELEASES}/${NAME}/${VERSION}/${NAME}_${VERSION}_SHA256SUMS.sig && \
    gpg --batch --verify ${NAME}_${VERSION}_SHA256SUMS.sig ${NAME}_${VERSION}_SHA256SUMS && \
    grep ${NAME}_${VERSION}_linux_${ARCH}.zip ${NAME}_${VERSION}_SHA256SUMS | sha256sum -c && \
    unzip -d /bin ${NAME}_${VERSION}_linux_${ARCH}.zip

FROM hashicorp/consul:1.9.5

# NAME = product name, ex: consul-ecs
# VERSION = product version, ex: 1.2.3
ARG NAME=consul-ecs
ARG VERSION

LABEL maintainer="Consul Team <consul@hashicorp.com>"
LABEL version=$VERSION

# Create a non-root user to run the software.
RUN addgroup ${NAME} && \
    adduser -S -G ${NAME} ${NAME}

USER ${NAME}
COPY --from=BUILDER /bin/consul-ecs /bin/consul-ecs
ENTRYPOINT ["/bin/consul-ecs"]
