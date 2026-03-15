#!/bin/sh
sudo mkdir /run/sshd
sudo chmod 0755 /run/sshd
sudo apt-get update -y && sudo apt-get install -y gcc build-essential cpanminus cmake git libssh-dev vim libio-socket-ssl-perl libnet-ip-xs-perl libjson-xs-perl openssh-server netcat-traditional golang
git clone https://github.com/XiaoTianCan/stayrtr-SelectiveSync
cd stayrtr-SelectiveSync
go build cmd/stayrtr/stayrtr.go
go install cmd/stayrtr/stayrtr.go
go build cmd/rtr-client/main.go
go install cmd/rtr-client/main.go
sudo cp main ./rtr-client
sudo chmod 755 ./rtr-client
