# mkworld

zerotier生成world.bin

## mkworld.cpp

移动mkworld.cpp文件到zerotier /attic/world目录下编译

----------
linux直接编译
```
c++ -std=c++11 -I../.. -I../../ext -I.. -g -o mkworld ../../node/C25519.cpp ../../node/Salsa20.cpp ../../node/SHA512.cpp ../../node/Identity.cpp ../../node/Utils.cpp ../../node/InetAddress.cpp ../../osdep/OSUtils.cpp mkworld.cpp -lm
```
----------
win要加-lws2_32 建议使用msys2编译
```
c++ -std=c++11 -I../.. -I../../ext -I.. -g -o mkworld ../../node/C25519.cpp ../../node/Salsa20.cpp ../../node/SHA512.cpp ../../node/Identity.cpp ../../node/Utils.cpp ../../node/InetAddress.cpp ../../osdep/OSUtils.cpp mkworld.cpp -lm -lws2_32
```

## main.py
mkworld的python版本

基本逻辑弄好了 得改改才能用