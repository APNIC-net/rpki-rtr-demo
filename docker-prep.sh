#!/bin/sh
sudo mkdir /run/sshd
sudo chmod 0755 /run/sshd
sudo apt-get update -y && sudo apt-get install -y gcc build-essential cpanminus cmake git libssh-dev stayrtr rustup vim libio-socket-ssl-perl libnet-ip-xs-perl libjson-xs-perl openssh-server netcat-traditional
rustup default stable
cargo install rtrtr
