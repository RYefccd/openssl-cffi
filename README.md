openssl-cffi
============


    # system libraries
    apt-get install build-essential python3-dev libffi-dev
    # python libraries
    python3 -m pip install cffi


download gmssl(openssl fork, surpport sm2, sm3, sm4), and compile it
docs: http://gmssl.org/docs/quickstart.html

after install gmssl,

    python3 openssl-cffi.py


上面的实现了 python 通过调用 gmssl 中的 aes 算法. 之后会使用此方法调用gmssl 中的 sm2, sm4.



下面的链接是 openssl 1.0.x 的实现, 有些接口发生了变化.
gmssl 是基于 openssl 1.1.x 的 fork 版本, 所以有些EVP的接口发生了变化, 以我的实际代码为准， 这个说明我得抽时间改下.
调用细节以我的实际代码openssl-cffi.py 为准，原理不变, 可以参考这个文档.

This is example code for wrapping openssl with cffi. More information in the blog post:

[Using Openssl From Python With `python-cffi`](https://gist.github.com/vishvananda/980132c0970f8621bb3c)
