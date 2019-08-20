#!/bin/sh

git submodule init && git submodule update

cd opt

# Golang
GOLANG_VERSION=1.12.7
GOLANG_HASH=66d83bfb5a9ede000e33c6579a91a29e6b101829ad41fffb5c5bb6c900e109d9
if [ ! -f "go${GOLANG_VERSION}.linux-amd64.tar.gz" ]; then
    echo "downloading go${GOLANG_VERSION}.linux-amd64.tar.gz"
    curl -O https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz
fi
echo "${GOLANG_HASH}  go${GOLANG_VERSION}.linux-amd64.tar.gz" | sha256sum -c

# Cmake
CMAKE_VERSION=3.14.0
CMAKE_VERSION_DOT=v3.14
CMAKE_HASH=aa76ba67b3c2af1946701f847073f4652af5cbd9f141f221c97af99127e75502
if [ ! -f "cmake-${CMAKE_VERSION}.tar.gz" ]; then
    echo "downloading cmake-${CMAKE_VERSION}.tar.gz"
    curl -O https://cmake.org/files/${CMAKE_VERSION_DOT}/cmake-${CMAKE_VERSION}.tar.gz
fi
echo "${CMAKE_HASH}  cmake-${CMAKE_VERSION}.tar.gz" | sha256sum -c

# Boost
BOOST_VERSION=1_69_0
BOOST_VERSION_DOT=1.69.0
BOOST_HASH=8f32d4617390d1c2d16f26a27ab60d97807b35440d45891fa340fc2648b04406
if [ ! -f "boost_${BOOST_VERSION}.tar.bz2" ]; then
    echo "downloading boost_${BOOST_VERSION}.tar.bz2"
    curl -L -o  boost_${BOOST_VERSION}.tar.bz2 https://dl.bintray.com/boostorg/release/${BOOST_VERSION_DOT}/source/boost_${BOOST_VERSION}.tar.bz2
fi
echo "${BOOST_HASH}  boost_${BOOST_VERSION}.tar.bz2" | sha256sum -c

# OpenSSL
OPENSSL_VERSION=1.1.1b
OPENSSL_HASH=5c557b023230413dfb0756f3137a13e6d726838ccd1430888ad15bfb2b43ea4b
if [ ! -f "openssl-${OPENSSL_VERSION}.tar.gz" ]; then
    echo "downloading openssl-${OPENSSL_VERSION}.tar.gz"
    curl -s -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
fi
echo "${OPENSSL_HASH}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c

# ZMQ
ZMQ_VERSION=v4.3.1
ZMQ_HASH=2cb1240db64ce1ea299e00474c646a2453a8435b
if [ ! -d "libzmq" ]; then
    git clone https://github.com/zeromq/libzmq.git -b ${ZMQ_VERSION}
    cd libzmq && test `git rev-parse HEAD` = ${ZMQ_HASH} || exit 1
    cd ..
fi

# zmq.hpp
CPPZMQ_VERSION=v4.3.0
CPPZMQ_HASH=213da0b04ae3b4d846c9abc46bab87f86bfb9cf4
if [ ! -d "cppzmq" ]; then
    git clone https://github.com/zeromq/cppzmq.git -b ${CPPZMQ_VERSION}
    cd cppzmq && test `git rev-parse HEAD` = ${CPPZMQ_HASH} || exit 1
    cd ..
fi

# Sodium
SODIUM_VERSION=1.0.17
SODIUM_HASH=b732443c442239c2e0184820e9b23cca0de0828c
if [ ! -d "libsodium" ]; then
    git clone https://github.com/jedisct1/libsodium.git -b ${SODIUM_VERSION}
    cd libsodium && test `git rev-parse HEAD` = ${SODIUM_HASH} || exit 1
    cd ..
fi

cd ..

docker image build -f Dockerfile.xcrypto -t lk:xcrypto .
