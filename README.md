# Smart DNS
Smart Dns RUST实现智能DNS  对标Dnspod

### 分支
- try (dns proto 剖析)
- dev 
- master 


RUST依赖glibc  这个最好版本低一点 不然一些老系统无法运行
```shell script
[target.x86_64-unknown-linux-musl]
linker = "x86_64-openwrt-linux-gcc"
ar = "x86_64-openwrt-linux-ar"

cargo build --target x86_64-unknown-linux-musl --release
CC_x86_64_unknown_linux_musl="x86_64-openwrt-linux-gcc"  cargo build --target x86_64-unknown-linux-musl --release
```
