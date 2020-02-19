FROM debian:stretch-slim

ARG BOOST_VERSION=1.62.0
ARG ZMQ_VERSION=5
ARG DB_VERSION=5.3

RUN useradd -r platincoin \
    && apt-get update -y \
    && apt-get -o APT::Get::Install-Recommends=0 -o APT::Get::Install-Suggests=0 install -y \
    libboost-system${BOOST_VERSION} libboost-filesystem${BOOST_VERSION} libboost-chrono${BOOST_VERSION} \
    libboost-program-options${BOOST_VERSION} libboost-thread${BOOST_VERSION} libzmq${ZMQ_VERSION} \
    libdb++${DB_VERSION} libminiupnpc10 libevent-pthreads-2.0-5 libevent-2.0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && set -ex
