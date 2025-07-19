#!/bin/sh

# Must be run from a directory containing the repository content.

sudo mkdir /run/sshd
sudo chmod 0755 /run/sshd
sudo apt-get update -y && sudo apt-get install -y gcc build-essential cpanminus cmake git libssh-dev rustc cargo stayrtr rustup vim
rustup default stable
cargo install rtrtr
export PATH=$PATH:/root/.cargo/bin

git clone https://github.com/tanneberger/rtrlib
cd rtrlib
git checkout aspa-fixes
sed -i 's/case EOD:/case EOD:\n;/' rtrlib/rtr/packets.c
rm doxygen/examples/rtr_mgr.c
cat doxygen/examples/CMakeLists.txt | grep -v rtr_mgr > asdf; mv asdf doxygen/examples/CMakeLists.txt
cmake -D CMAKE_BUILD_TYPE=Debug . && make && sudo make install
cd .. && rm -rf rtrlib

export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
sudo ldconfig
curl -JLO "https://dl.filippo.io/mkcert/latest?for=linux/amd64"
chmod +x mkcert-v*-linux-amd64
cp mkcert-v*-linux-amd64 /usr/local/bin/mkcert

sudo cpanm -v --installdeps .
sudo make clean || true
perl Makefile.PL && make
