import sys
import socket
import threading
import pysodium
import hashlib
from time import sleep

# 协议常量
MAX_ID_BYTES = 64
CRYPTO_CORE_RISTRETTO255_BYTES = 32
CRYPTO_CORE_RISTRETTO255_SCALARBYTES = 32



def read_password_file(filename):
    """读取密码文件（与之前实现一致）"""
    with open(filename, 'rb') as f:
        data = f.read()

    network_end = data.find(b'\x00')
    network = data[:network_end].decode('utf-8')
    remaining = data[network_end + 1:]

    ID = remaining[:MAX_ID_BYTES]
    Xi = remaining[MAX_ID_BYTES:MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES]
    Yi = remaining[MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES:MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES]
    zi = remaining[MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES:]

    return network, ID, Xi, Yi, zi


def tagged_hash(tag, *chunks):
    """带标签的哈希函数"""
    h = hashlib.sha512()
    h.update(tag.to_bytes(4, 'big', signed=False))
    for data, length in chunks:
        h.update(data[:length])
    return h.digest()


def receive_exact(sock, expected_len):
    """确保接收指定长度的数据"""
    data = b''
    while len(data) < expected_len:
        remaining = expected_len - len(data)
        data += sock.recv(4096 if remaining > 4096 else remaining)
    return data


class P2PNode:
    def __init__(self, password_file):
        self.network, self.ID, self.X, self.Y, self.z = read_password_file(password_file)
        self.local_r = pysodium.crypto_core_ristretto255_scalar_random()
        self.local_R = pysodium.crypto_scalarmult_ristretto255_base(self.local_r)
        self.peer_params = None
        self.shared_key = None

    def calculate_shared_secret(self, peer_ID, peer_X, peer_R):
        try:
            # 添加类型和长度校验
            assert isinstance(peer_ID, bytes) and len(peer_ID) == MAX_ID_BYTES
            assert isinstance(peer_X, bytes) and len(peer_X) == CRYPTO_CORE_RISTRETTO255_BYTES
            assert isinstance(peer_R, bytes) and len(peer_R) == CRYPTO_CORE_RISTRETTO255_BYTES

            # 计算alpha
            alpha = pysodium.crypto_scalarmult_ristretto255(self.local_r, peer_R)

            # 计算哈希系数
            network_bytes = self.network.encode('utf-8')  # 明确编码格式
            hj_hash = tagged_hash(2,
                                  (network_bytes, len(network_bytes)),
                                  (peer_ID, MAX_ID_BYTES),
                                  (peer_X, CRYPTO_CORE_RISTRETTO255_BYTES))
            hj = pysodium.crypto_core_ristretto255_scalar_reduce(hj_hash)

            # 中间值计算
            Y_hj = pysodium.crypto_scalarmult_ristretto255(hj, self.Y)
            sum_point = pysodium.crypto_core_ristretto255_add(
                peer_R,
                pysodium.crypto_core_ristretto255_add(peer_X, Y_hj)
            )

            # 标量运算
            r_zi = pysodium.crypto_core_ristretto255_scalar_add(self.local_r, self.z)

            # 计算beta
            beta = pysodium.crypto_scalarmult_ristretto255(r_zi, sum_point)

            # 确定会话顺序（大端字节序比较）
            is_initiator = bytes(self.local_R) > bytes(peer_R)

            # 构造哈希输入
            hash_input = b''.join([
                network_bytes,
                alpha,
                beta,
                self.ID if is_initiator else peer_ID,
                self.X if is_initiator else peer_X,
                self.local_R if is_initiator else peer_R,
                peer_ID if is_initiator else self.ID,
                peer_X if is_initiator else self.X,
                peer_R if is_initiator else self.local_R
            ])

            # 生成最终密钥
            h = hashlib.sha256()
            h.update(pysodium.crypto_hash_sha256(hash_input))
            shared_key = h.digest()
            print(f"\n[SUCCESS] Shared Key: {shared_key.hex()}\n")
            return shared_key
        except Exception as e:
            print(f"[ERROR] Key calculation failed: {type(e).__name__} - {str(e)}")
            return None

    def listen_thread(self, port):
        """监听线程实现"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen()
            print(f"Listening on port {port}...")

            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Accepted connection from {addr}")
                    # 接收对端参数
                    data = receive_exact(conn, MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES)
                    peer_ID = data[:MAX_ID_BYTES]
                    peer_X = data[MAX_ID_BYTES:MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES]
                    peer_R = data[MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES:]

                    # 发送本地参数
                    conn.sendall(self.ID + self.X + self.local_R)

                    # 计算共享密钥
                    self.shared_key = self.calculate_shared_secret(peer_ID, peer_X, peer_R)
                    if self.shared_key:
                        print(f"Shared Key: {self.shared_key.hex()}")

    def connect_thread(self, host, port):
        """主动连接线程"""
        sleep(1)  # 确保监听端先启动
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect((host, port))
                print(f"Connected to {host}:{port}")
                # 发送本地参数
                s.sendall(self.ID + self.X + self.local_R)
                # 接收对端参数
                data = receive_exact(s, MAX_ID_BYTES + 2 * CRYPTO_CORE_RISTRETTO255_BYTES)
                peer_ID = data[:MAX_ID_BYTES]
                peer_X = data[MAX_ID_BYTES:MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES]
                peer_R = data[MAX_ID_BYTES + CRYPTO_CORE_RISTRETTO255_BYTES:]

                # 计算共享密钥
                self.shared_key = self.calculate_shared_secret(peer_ID, peer_X, peer_R)
                if self.shared_key:
                    print(f"Shared Key: {self.shared_key.hex()}")
            except ConnectionRefusedError:
                print("Connection refused, retrying...")
                sleep(1)
                self.connect_thread(host, port)


def main():
    if len(sys.argv) < 3:
        print("Usage: python peer.py <password-file> <listen-port> [connect-host] [connect-port]")
        sys.exit(1)

    node = P2PNode(sys.argv[1])
    listen_port = int(sys.argv[2])

    # 启动监听线程
    threading.Thread(target=node.listen_thread, args=(listen_port,), daemon=True).start()

    # 如果有连接参数则启动主动连接
    if len(sys.argv) > 3:
        connect_host = sys.argv[3]
        connect_port = int(sys.argv[4]) if len(sys.argv) > 4 else listen_port
        threading.Thread(target=node.connect_thread, args=(connect_host, connect_port)).start()

    # 保持主线程运行
    while True: sleep(1)


if __name__ == "__main__":
    main()