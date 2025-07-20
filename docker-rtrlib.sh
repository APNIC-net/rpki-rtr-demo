#!/bin/sh
git clone https://github.com/rtrlib/rtrlib
cd rtrlib
git checkout hackathon-ietf-123-aspa-and-rpki-upgrade
sed -i 's/case EOD:/case EOD:\n;/' rtrlib/rtr/packets.c
rm doxygen/examples/rtr_mgr.c
cat doxygen/examples/CMakeLists.txt | grep -v rtr_mgr > asdf; mv asdf doxygen/examples/CMakeLists.txt
cmake -D CMAKE_BUILD_TYPE=Debug . && make && sudo make install
cd .. && rm -rf rtrlib
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
sudo ldconfig
