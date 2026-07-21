#!/bin/sh
git clone https://github.com/rtrlib/rtrlib
cd rtrlib
cmake -D CMAKE_BUILD_TYPE=Debug . && make && sudo make install
cd .. && rm -rf rtrlib
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64
sudo ldconfig
