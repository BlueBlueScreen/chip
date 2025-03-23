import sys
import socket
import pysodium
import hashlib

# 修改MAX_ID_BYTES为64以匹配pwfile_gen.py
MAX_ID_BYTES = 64
CRYPTO_CORE_RISTRETTO255_BYTES = 32
CRYPTO_CORE_RISTRETTO255_SCALARBYTES = 32

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
        print(f"Usage: {sys.argv[0]} <password-file> [[<ip>] <port>]")
        sys.exit(1)

    network, IDi, Xi, Yi, zi = read_password_file(sys.argv[1])

    r = pysodium.crypto_core_ristretto255_scalar_random()
    Ri = pysodium.crypto_scalarmult_ristretto255_base(r)

    ip = sys.argv[-2] if len(sys.argv) > 3 else 'localhost'
    port = int(sys.argv[-1]) if len(sys.argv) > 2 else 9999
    sock = connect_socket(ip, port)

    try:
        sock.sendall(IDi + Xi + Ri)

        data = b''
        expected_len = MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES
        while len(data) < expected_len:
            data += sock.recv(4096)

        IDj = data[:MAX_ID_BYTES]
        Xj = data[MAX_ID_BYTES:MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES]
        Rj = data[MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES:expected_len]

        print(f"Identified: {IDj.decode('utf-8', errors='replace').rstrip(chr(0))}")

        alpha = pysodium.crypto_scalarmult_ristretto255(r, Rj)

        # 修复tagged_hash调用，传递正确的bytes参数
        hj_hash = tagged_hash(2, network.encode(), IDj, Xj)
        hj = pysodium.crypto_core_ristretto255_scalar_reduce(hj_hash)

        Yi_hj = pysodium.crypto_scalarmult_ristretto255(hj, Yi)

        Rj_Xj_Yi_hj = pysodium.crypto_core_ristretto255_add(
            Rj,
            pysodium.crypto_core_ristretto255_add(Xj, Yi_hj)
        )

        r_zi = pysodium.crypto_core_ristretto255_scalar_add(r, zi)
        beta = pysodium.crypto_scalarmult_ristretto255(r_zi, Rj_Xj_Yi_hj)

        is_first = Ri >= Rj  # 直接比较字节

        # 修复S的计算，直接哈希连接后的数据
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
        h = hashlib.sha256()
        h.update(combined)
        S = h.digest()

        print("Shared secret:", S.hex())  # 输出共享密钥以便验证

    finally:
        sock.close()

if __name__ == "__main__":
    protocol_execution()