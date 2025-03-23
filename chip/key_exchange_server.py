import sys
import socket
import pysodium
import hashlib

# 修改MAX_ID_BYTES为64以匹配pwfile_gen.py
MAX_ID_BYTES = 64
CRYPTO_CORE_RISTRETTO255_BYTES = 32
CRYPTO_CORE_RISTRETTO255_SCALARBYTES = 32

def create_server(port):
    #创建一个TCP接口，指定了使用IPv4地址族
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #涉及TCP的参数，表示不管拥塞，可以减少延迟
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    #表示接受所有可以连接的端口
    sock.bind(('0.0.0.0', port))
    #使套接字进入监听状态，准备接受连接
    sock.listen(1)
    return sock

def read_password_file(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    network_end = data.find(b'\x00')
    network = data[:network_end].decode('utf-8')
    remaining = data[network_end + 1:]

    # 根据新的MAX_ID_BYTES解析字段
    IDi = remaining[:MAX_ID_BYTES]
    remaining = remaining[MAX_ID_BYTES:]
    Xi = remaining[:CRYPTO_CORE_RISTRETTO255_BYTES]
    remaining = remaining[CRYPTO_CORE_RISTRETTO255_BYTES:]
    Yi = remaining[:CRYPTO_CORE_RISTRETTO255_BYTES]
    remaining = remaining[CRYPTO_CORE_RISTRETTO255_BYTES:]
    zi = remaining[:CRYPTO_CORE_RISTRETTO255_SCALARBYTES]

    return network, IDi, Xi, Yi, zi

def tagged_hash(tag: int, *data_bytes_list: bytes) -> bytes:
    h = hashlib.sha512()
    h.update(tag.to_bytes(4, 'big'))
    for data_bytes in data_bytes_list:
        h.update(len(data_bytes).to_bytes(8, 'big'))
        h.update(data_bytes)
    return h.digest()

def connect_socket(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect((ip, port))
    return sock


def protocol_execution():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print(f"Usage: {sys.argv[0]} <password-file> [--listen | <ip> <port>]")
        sys.exit(1)

    # 读取密码文件
    network, IDi, Xi, Yi, zi = read_password_file(sys.argv[1])

    # 生成随机标量r
    r = pysodium.crypto_core_ristretto255_scalar_random()
    Ri = pysodium.crypto_scalarmult_ristretto255_base(r)

    # 判断运行模式
    is_server = '--listen' in sys.argv
    if is_server:
        # 服务端模式
        port = int(sys.argv[-1]) if len(sys.argv) > 3 else 9999
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        listen_sock.bind(('0.0.0.0', port))
        listen_sock.listen(1)
        print(f"Listening on port {port}...")
        sock, addr = listen_sock.accept()
        listen_sock.close()
    else:
        # 客户端模式
        ip = sys.argv[-2] if len(sys.argv) > 3 else 'localhost'
        port = int(sys.argv[-1]) if len(sys.argv) > 2 else 9999
        sock = connect_socket(ip, port)

    try:
        if is_server:
            # 服务端先收后发
            data = b''
            expected_len = MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES
            while len(data) < expected_len:
                data += sock.recv(4096)

            # 发送响应
            sock.sendall(IDi + Xi + Ri)
        else:
            # 客户端先发后收
            sock.sendall(IDi + Xi + Ri)
            data = b''
            expected_len = MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES
            while len(data) < expected_len:
                data += sock.recv(4096)

        # 解析对方数据
        IDj = data[:MAX_ID_BYTES]
        Xj = data[MAX_ID_BYTES:MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES]
        Rj = data[MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES:expected_len]

        # 清理ID中的空字节
        clean_idj = IDj.decode('utf-8', errors='replace').rstrip('\x00')
        print(f"Identified: {clean_idj}")

        # 计算共享密钥
        alpha = pysodium.crypto_scalarmult_ristretto255(r, Rj)
        hj_hash = tagged_hash(2, network.encode(), IDj, Xj)
        hj = pysodium.crypto_core_ristretto255_scalar_reduce(hj_hash)
        Yi_hj = pysodium.crypto_scalarmult_ristretto255(hj, Yi)

        # 计算中间值
        Xj_Yi_hj = pysodium.crypto_core_ristretto255_add(Xj, Yi_hj)
        Rj_Xj_Yi_hj = pysodium.crypto_core_ristretto255_add(Rj, Xj_Yi_hj)

        # 计算beta
        r_zi = pysodium.crypto_core_ristretto255_scalar_add(r, zi)
        beta = pysodium.crypto_scalarmult_ristretto255(r_zi, Rj_Xj_Yi_hj)

        # 确定会话顺序
        is_first = Ri >= Rj  # 字节比较

        # 计算最终密钥
        combined = b''.join([
            network.encode(),
            alpha,
            beta,
            IDi if is_first else IDj,
            Xi if is_first else Xj,
            Ri if is_first else Rj,
            IDj if is_first else IDi,
            Xj if is_first else Xi,
            Rj if is_first else Ri
        ])
        S = hashlib.sha256(combined).digest()
        print(f"Shared secret: {S.hex()}")

    finally:
        sock.close()

if __name__ == "__main__":
    protocol_execution()