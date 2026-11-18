"""生成 PKI 证书链：根 CA -> 服务器证书 + 各用户客户端证书（双向 TLS）。

用法: python scripts/gen_certs.py [用户名1 用户名2 ...]
默认为演示用户 alice bob guest 签发客户端证书。
证书输出到 certs/ 目录，private key 权限按课程演示场景放宽，
生产环境应改用硬件保护或密钥管理系统。
"""

import datetime
import ipaddress
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs")
USERS = ["alice", "bob", "guest"]
DAYS = 365


def gen_key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def write_pem(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
    print("  写出", os.path.basename(path))


def build_ca() -> tuple:
    key = gen_key(4096)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecFT Root CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def build_leaf(ca_key, ca_cert, cn: str, kind: str, san_ips=(), san_dns=()) -> tuple:
    """kind: 'server' -> serverAuth；'client' -> clientAuth。"""
    key = gen_key(2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(subject).issuer_name(ca_cert.subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=DAYS))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(
                   digital_signature=True, key_encipherment=True,
                   content_commitment=False, data_encipherment=False, key_agreement=False,
                   key_cert_sign=False, crl_sign=False,
                   encipher_only=False, decipher_only=False), critical=True))
    names = []
    for ip in san_ips:
        names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    for dns in san_dns:
        names.append(x509.DNSName(dns))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    # RFC 5280 规范扩展：Python 3.13 的 OpenSSL 默认开启 VERIFY_X509_STRICT，
    # 缺少 SKI/AKI 的证书会被严格校验拒绝
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                                    critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                                    critical=False)
    eku = (x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
           if kind == "server"
           else x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]))
    builder = builder.add_extension(eku, critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def export(cert, name: str) -> None:
    write_pem(os.path.join(CERTS, f"{name}.pem"), cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    users = sys.argv[1:] or USERS
    os.makedirs(CERTS, exist_ok=True)
    print("[1/3] 生成根 CA ...")
    ca_key, ca_cert = build_ca()
    export(ca_cert, "ca-cert")
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    print("[2/3] 生成服务器证书 (CN=localhost) ...")
    key, cert = build_leaf(ca_key, ca_cert, "localhost", "server",
                           san_ips=[ipaddress.ip_address("127.0.0.1")], san_dns=["localhost"])
    write_pem(os.path.join(CERTS, "server-cert.pem"), cert.public_bytes(serialization.Encoding.PEM))
    write_pem(os.path.join(CERTS, "server-key.pem"),
              key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()))
    # 服务器证书 + CA 链合并（TLS 握手需返回完整链）
    with open(os.path.join(CERTS, "server-cert.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        f.write(ca_pem)

    print("[3/3] 为用户签发客户端证书 ...")
    for u in users:
        key, cert = build_leaf(ca_key, ca_cert, u, "client")
        # 合并证书与私钥为单文件，便于客户端一键加载
        data = cert.public_bytes(serialization.Encoding.PEM)
        data += key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption())
        write_pem(os.path.join(CERTS, f"client_{u}.pem"), data)
    print("完成。证书目录:", CERTS)


if __name__ == "__main__":
    main()
