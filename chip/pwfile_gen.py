import sys
import hashlib
import pysodium


def tagged_hash(tag: int, *data_bytes_list: bytes) -> bytes:
    h = hashlib.sha512()
    h.update(tag.to_bytes(4, 'big'))
    for data_bytes in data_bytes_list:
        h.update(len(data_bytes).to_bytes(8, 'big'))
        h.update(data_bytes)
    return h.digest()


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <network> <password> <identity>", file=sys.stderr)
        sys.exit(1)

    network = sys.argv[1].encode()
    password = sys.argv[2].encode()
    identity = sys.argv[3]
    filename = f"{identity}.bin"  # 生成文件名

    with open(filename, 'wb') as f:  # 打开二进制文件
        # 写入网络标识
        f.write(network + b'\x00')

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

        # 处理身份标识
        MAX_ID_BYTES = 64
        id_bytes = identity.encode()
        if len(id_bytes) > MAX_ID_BYTES:
            print(f"Identity exceeds {MAX_ID_BYTES} bytes: {identity}", file=sys.stderr)
            sys.exit(1)
        f.write(id_bytes.ljust(MAX_ID_BYTES, b'\x00'))

        # 生成临时密钥对
        x = pysodium.crypto_core_ristretto255_scalar_random()
        X = pysodium.crypto_scalarmult_ristretto255_base(x)
        f.write(X)

        # 生成密码相关密钥
        y = pysodium.crypto_core_ristretto255_scalar_reduce(pwd_hash)
        Y = pysodium.crypto_scalarmult_ristretto255_base(y)
        f.write(Y)

        # 计算身份哈希
        id_hash = tagged_hash(2, network, id_bytes.ljust(MAX_ID_BYTES, b'\x00'), X)
        h = pysodium.crypto_core_ristretto255_scalar_reduce(id_hash)

        # 计算最终签名
        yh = pysodium.crypto_core_ristretto255_scalar_mul(y, h)
        z = pysodium.crypto_core_ristretto255_scalar_add(yh, x)
        f.write(z)


if __name__ == '__main__':
    main()