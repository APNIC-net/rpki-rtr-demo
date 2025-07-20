#!/bin/sh
git clone https://github.com/tanneberger/rtrlib
cd rtrlib
git checkout aspa-fixes
sed -i 's/case EOD:/case EOD:\n;/' rtrlib/rtr/packets.c
rm doxygen/examples/rtr_mgr.c
cat doxygen/examples/CMakeLists.txt | grep -v rtr_mgr > asdf; mv asdf doxygen/examples/CMakeLists.txt
cmake -D CMAKE_BUILD_TYPE=Debug . && make && sudo make install
cd .. && rm -rf rtrlib
