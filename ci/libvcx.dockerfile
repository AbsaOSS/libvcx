ARG ALPINE_CORE_IMAGE
FROM ${ALPINE_CORE_IMAGE} as builder
USER indy
WORKDIR /home/indy

COPY --chown=indy  ./ ./

USER indy
ENV X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_NO_VENDOR "true"
RUN cargo build --release --manifest-path=/home/indy/Cargo.toml

USER root
RUN mv /home/indy/target/release/libvcx.so .

FROM alpine:3.12

ARG UID=1000
ARG GID=1000

RUN addgroup -g $GID node && adduser -u $UID -D -G node node

COPY --from=builder /usr/lib/libindy.so /home/indy/lib*.so /usr/lib/

WORKDIR /home/node
COPY --chown=node ./libvcx ./libvcx
COPY --chown=node ./agency_client ./agency_client
COPY --chown=node ./wrappers/node ./wrappers/node
COPY --chown=node ./agents/node ./agents/node

RUN echo '@alpine38 http://dl-cdn.alpinelinux.org/alpine/v3.8/main' >> /etc/apk/repositories

RUN apk update && apk upgrade
RUN apk add --no-cache \
        bash \
        curl \
        g++ \
        gcc \
        git \
        libsodium-dev \
        libzmq \
        nodejs \
        npm \
        make \
        openssl-dev \
        python2 \
        zeromq-dev

USER node

ARG RUST_VER="1.53.0"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain $RUST_VER --default-host x86_64-unknown-linux-musl
ENV PATH="/home/node/.cargo/bin:$PATH" RUSTFLAGS="-C target-feature=-crt-static"

# copy cargo caches - this way we don't have to redownload dependencies on subsequent builds
RUN mkdir -p /home/node/.cargo/registry
COPY --from=builder /home/indy/.cargo/registry /home/node/.cargo/registry
RUN chown -R node:node /home/node/.cargo/registry
