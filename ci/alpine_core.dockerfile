FROM alpine:3.12 AS builder

ARG UID=1000
ARG GID=1000

ARG INDYSDK_PATH=/home/indy/indy-sdk
ARG INDYSDK_REPO=https://github.com/hyperledger/indy-sdk.git
ARG INDYSDK_REVISION=efb7215

ENV RUST_LOG=warning

RUN addgroup -g $GID indy && adduser -u $UID -D -G indy indy

RUN apk update && apk upgrade && \
    apk add --no-cache \
        build-base \
        git \
        curl \
        libsodium-dev \
        libzmq \
        openssl-dev \
        zeromq-dev

USER indy
WORKDIR /home/indy

ARG RUST_VER="1.53.0"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain $RUST_VER --default-host x86_64-unknown-linux-musl
ENV PATH="/home/indy/.cargo/bin:$PATH" RUSTFLAGS="-C target-feature=-crt-static"

RUN git clone $INDYSDK_REPO && cd indy-sdk && git checkout $INDYSDK_REVISION

RUN cargo build --release --manifest-path=$INDYSDK_PATH/libindy/Cargo.toml

USER root
RUN mv $INDYSDK_PATH/libindy/target/release/libindy.so /usr/lib

USER indy
RUN cargo build --release --manifest-path=$INDYSDK_PATH/libnullpay/Cargo.toml
RUN cargo build --release --manifest-path=$INDYSDK_PATH/experimental/plugins/postgres_storage/Cargo.toml

USER root
RUN mv $INDYSDK_PATH/libnullpay/target/release/libnullpay.so .
RUN mv $INDYSDK_PATH/experimental/plugins/postgres_storage/target/release/libindystrgpostgres.so .
