# 山东城商服务端部署

考虑加解密的效率, 在验证码服务端使用 c 库来完成加解密, 然后使用
python 封装调用 c 库的方法来提高解密的效率(直接把后续解密的优化实现).

提纲:

  - 编译工具 (gcc make 等)
            
        # ubuntu
        sudo apt-get install build-essential
        # centos
        sudo yum groupinstall 'Development Tools'
        
  - 编译安装 gmssl （提供 sm2, sm4 算法支持）
  - python 库依赖

        pip install cffi

### 编译工具
  - ubuntu
    
        sudo apt-get install build-essential
  - centos
    
        sudo yum groupinstall 'Development Tools'

### gmssl


1. 下载源代码([zip])，解压缩至当前工作目录
2. 编译源码

       $ ./config no-saf no-sdf no-skf no-sof no-zuc
       $ make
       $ sudo make install

3. 安装之后可以执行gmssl命令行工具检查是否成功

       $ gmssl version
       GmSSL 2.0 - OpenSSL 1.1.0d
       
    如果编译遇到

       rror： while loading shared libraries: libssl.so.1.1: cannot open shared object file: No such file or directory
       gmssl: symbol BIO_debug_callback version OPENSSL_1_1_0d not defined in file libcrypto.so.1.1 with link time reference

    此类问题，可通过如下命令解决

       $ export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH


###  python 库依赖

       pip install cffi



   [zip]: <https://github.com/guanzhi/GmSSL/archive/master.zip>
   
   
###  sm2测试



###  sm4测试

















openssl-cffi 参考资料
========================


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



c语言 demo
====================================

安装好 gmssl 后,  执行下列代码测试

    gcc geetest_sm2_test.c -o test -lcrypto
    ./test


sm2tool.py 包含相关的 asn.1/der 和 sm2 密文 c1c3c2 之间的转换函数.
