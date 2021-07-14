FROM ubuntu:18.04 as BASE

ARG UID=1000

ARG INDYSDK_PATH=/home/indy/indy-sdk
ARG INDYSDK_REVISION=efb7215
ARG INDYSDK_REPO=https://github.com/hyperledger/indy-sdk
ARG RUST_VER=nightly-2021-07-05

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
      apt-transport-https \
      build-essential \
      ca-certificates \
      cmake \
      curl \
      debhelper \
      devscripts \
      git \
      libssl-dev \
      libsqlite3-dev \
      libzmq3-dev \
      libzmq5 \
      pkg-config

# Install libsodium
RUN cd /tmp && \
   curl https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz | tar -xz && \
    cd /tmp/libsodium-1.0.18 && \
    ./configure && \
    make && \
    make install && \
    rm -rf /tmp/libsodium-1.0.18

RUN useradd -ms /bin/bash -u $UID indy

USER indy
WORKDIR /home/indy
COPY --chown=indy ./ aries-vcx/

# Install Rust toolchain
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${RUST_VER}
ENV PATH /home/indy/.cargo/bin:$PATH

# Clone and build indy-sdk
WORKDIR /home/indy
RUN git clone $INDYSDK_REPO && \
    cd $INDYSDK_PATH && git checkout $INDYSDK_REVISION
RUN cargo build --release --manifest-path=$INDYSDK_PATH/libindy/Cargo.toml

USER root
RUN mv /home/indy/indy-sdk/libindy/target/release/*.so /usr/lib

# Build indy binaries and move to system library
USER indy
RUN cargo build --release --manifest-path=$INDYSDK_PATH/libnullpay/Cargo.toml
RUN cargo build --release --manifest-path=$INDYSDK_PATH/experimental/plugins/postgres_storage/Cargo.toml
RUN cargo build --release --manifest-path=/home/indy/aries-vcx/Cargo.toml

USER root
RUN mv /home/indy/indy-sdk/libnullpay/target/release/*.so \
    /home/indy/indy-sdk/experimental/plugins/postgres_storage/target/release/*.so \
    /usr/local/lib/libsodium.* \
    /usr/lib/x86_64-linux-gnu/libssl* \
    /usr/lib

USER indy

RUN cargo install grcov
