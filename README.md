# Chip
It's a project that realizes chip(ipake instance in python)
***
  
In an unmanned scenario, to ensure secure communication between devices and between the device owner (user) and the device, the commonly adopted method is to equip each device with the same password or key. Then, using symmetric cryptography-based authentication key negotiation, the identities of the parties are mutually authenticated, and a common session key is obtained, which is used to encrypt subsequent communication content to ensure the security of the communication. In such a case, if one device is compromised or falls into the hands of an adversary, the security of all devices is compromised. In 2022, Cremer first proposed a solution to this problem, known as the identity-bound authenticated key agreement protocol. This protocol satisfies the condition that even if one device is captured by an adversary, the adversary can only impersonate that specific device, but not deceive by impersonating other devices.

Cremer realizes his scheme called chip in cpp [chipandcrisp](https://github.com/search?q=chipandcrisp&type=repositories) In this work, we choose to realizes chip in python.

##代码详解(pwfile_gen.py)
（用英文实在写不下去了，还是用中文介绍吧）

我们选择python中自带的标准加密库（pysodium,hashlib)来实现chip中所用到的哈希函数，群操作
```
import sys
import hashlib
import pysodium
```

因为在chip的实现中，我们有分隔哈希域的需求，因此我们自己实现`tagged_hash`函数，其可以接受多个字符格式的输入，并且将结果最后输出为一个64字节的二进制数
```
def tagged_hash(tag: int, *data_bytes_list: bytes) -> bytes:
#创建一个哈希函数对象
    h = hashlib.sha512()
#.update()方法可以将输入保存到哈希对象的缓冲区，其中tag.to_bytes是将tag转换为一个四字节的大端序，这是多数网络协议的标准的字节序
    h.update(tag.to_bytes(4, 'big'))
#这里就是将各种输入添加到哈希函数
    for data_bytes in data_bytes_list:
        h.update(len(data_bytes).to_bytes(8, 'big'))
        h.update(data_bytes)
#以二进制的格式输出哈希函数的结果
    return h.digest()
```

在主函数中，我们先检查用户运行程序时的输入数量正确与否
```
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <network> <password> <identity>", file=sys.stderr)
        sys.exit(1)
```

接下来就是正常读取参数，进行编码。并且生成文件，便于后续将程序输出的结果重定向到二进制文件中

接下来我们实现chip协议中`H（sid,pi)->y`流程
```
        # 生成salt
        salt_tagged = tagged_hash(1, network)
        salt = salt_tagged[:pysodium.crypto_pwhash_SALTBYTES]

        # 密码派生
        pwd_hash = pysodium.crypto_pwhash(
            pysodium.crypto_core_ristretto255_NONREDUCEDSCALARBYTES,
            password,
            salt,
            pysodium.crypto_pwhash_OPSLIMIT_SENSITIVE,
            pysodium.crypto_pwhash_MEMLIMIT_SENSITIVE,
            pysodium.crypto_pwhash_ALG_DEFAULT
        )
        # 生成密码相关密钥
        y = pysodium.crypto_core_ristretto255_scalar_reduce(pwd_hash)
        Y = pysodium.crypto_scalarmult_ristretto255_base(y)
        f.write(Y)
```
此处多提一嘴，pwd_hash的生成中参数 `pysodium.crypto_core_ristretto255_NONREDUCEDSCALARBYTE`是用来指定输出的长度的，最后pwd_hash的长度是64字节
But!
python中给的标准群运算（ristretto255椭圆曲线）实质上只能处理32字节的输入，因此我们还需要再对pwd_hash进行压缩才能得到实际上的KDC secret（y)

```
        # 生成临时密钥对
        x = pysodium.crypto_core_ristretto255_scalar_random()#随机生成临时密钥
        X = pysodium.crypto_scalarmult_ristretto255_base(x)
        f.write(X)
        # 计算身份哈希
        id_hash = tagged_hash(2, network, id_bytes.ljust(MAX_ID_BYTES, b'\x00'), X)
        h = pysodium.crypto_core_ristretto255_scalar_reduce(id_hash)

        # 计算最终签名
        yh = pysodium.crypto_core_ristretto255_scalar_mul(y, h)
        z = pysodium.crypto_core_ristretto255_scalar_add(yh, x)
        f.write(z)
if __name__ == '__main__':
    main()
```
在终端输入命令格式 `python pwfile_gen.py network password Alice` 就可以生成pwfile了

##代码详解（key_exchange阶段）
我们实现了多个版本的key_exchange逻辑，这里只解释key_exchange_server.py的内容，毕竟其他几个版本是AI写的
首先，我们读取pwfile.bin中的信息
```
def read_password_file(filename):
    """读取密码文件（与之前实现一致）"""
    with open(filename, 'rb') as f:
        data = f.read()

    network_end = data.find(b'\x00')#写入network的时候我们自个儿指定了结尾
    network = data[:network_end].decode('utf-8')
    remaining = data[network_end + 1:]

    ID = remaining[:MAX_ID_BYTES]
    Xi = remaining[MAX_ID_BYTES:MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES]
    Yi = remaining[MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES:MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES]
    zi = remaining[MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES:]

    return network, ID, Xi, Yi, zi
```
tagged_hash的实现不重复解释了

为了实现在公网上的传输，我们首先要建立一个TCP连接
```
def connect_socket(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect((ip, port))
    return sock
```
创建连接套接字并将其初始化

之后的流程中，要分为服务器端和客户端进行讨论（这里的服务器端仅位标识先发出共享密钥请求的参与方）
```
    # 判断运行模式
    is_server = '--listen' in sys.argv
    if is_server:
        # 服务端模式
        port = int(sys.argv[-1]) if len(sys.argv) > 3 else 9999
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#AF_INET指定使用IPv4地址族，SOCK_STREAM表示使用面向连接的TCP服务
        listen_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)#禁用Nagle算法，减少数据包的延迟
        listen_sock.bind(('0.0.0.0', port))
#只要端口正确就会进行监听，不会care其来自于哪一个网络接口
        listen_sock.listen(1)#限制最大连接数为1
        print(f"Listening on port {port}...")
        sock, addr = listen_sock.accept()
#accept会阻塞，指导接受到新的TCP连接
        listen_sock.close()
```
服务器端首先是创建一个监听套接字，默认监听的端口号为9999
```
        ip = sys.argv[-2] if len(sys.argv) > 3 else 'localhost'
        port = int(sys.argv[-1]) if len(sys.argv) > 2 else 9999
        sock = connect_socket(ip, port)
```
客户端要考虑的可就多了，得确定自己的ip地址，还要选择端口，还要连接服务器端



