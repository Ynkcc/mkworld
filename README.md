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

## mkworld.py
mkworld的python版本
具体调用方法可参考文件中的
```
if __name__ == '__main__':
    ...
```

## streamlit_deploy.py
使用streamlit框架的一个简易前端页面

本项目已托管在 [streamlit.io](https://share.streamlit.io/)

可通过以下链接直接访问

`https://mkworld.streamlit.app`

#### 自行部署参考命令

```
git clone https://github.com/Ynkcc/mkworld
cd mkworld
pip install -r requirements.txt
streamlit run streamlit_deploy.py
```