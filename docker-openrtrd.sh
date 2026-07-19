#!/bin/sh
set -e
mkdir /var/lib/rtrd
addgroup \
    --allow-bad-names \
    --gid 2000 \
    _rtrd && \
  adduser \
    --allow-bad-names \
    --home /var/lib/rtrd \
    --disabled-password \
    --gid 2000 \
    --uid 2000 \
    _rtrd
wget https://sobornost.net/~job/openrtrd.tar.gz
tar xf openrtrd.tar.gz
cd openrtrd
cp /openrtrd.patch .
patch -l -i openrtrd.patch
make
cp rtrd /usr/local/bin/
cp rtr-import /usr/local/bin/
