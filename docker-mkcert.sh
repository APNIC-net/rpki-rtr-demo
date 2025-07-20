#!/bin/sh
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
sudo ldconfig
curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
chmod +x mkcert-v*-linux-amd64
cp mkcert-v*-linux-amd64 /usr/local/bin/mkcert
