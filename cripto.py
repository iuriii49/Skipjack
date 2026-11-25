# Implementação da cifra Skipjack (FIPS PUB 185) com modos ECB e CBC
import struct
import secrets

# Tabela F utilizada nas operações internas da cifra
F_TABLE = [
    0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
    0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
    0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
    0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
    0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
    0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
    0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
    0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
    0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
    0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
    0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
    0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
    0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
    0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
    0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
    0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46
]


def permute_G(w: int, k_bytes: list[int]) -> int:
    g1, g2 = w >> 8, w & 0xFF
    g3 = F_TABLE[g2 ^ k_bytes[0]] ^ g1
    g4 = F_TABLE[g3 ^ k_bytes[1]] ^ g2
    g5 = F_TABLE[g4 ^ k_bytes[2]] ^ g3
    g6 = F_TABLE[g5 ^ k_bytes[3]] ^ g4
    return (g5 << 8) | g6


def inverse_permute_G(w: int, k_bytes: list[int]) -> int:
    g5, g6 = w >> 8, w & 0xFF
    g4 = F_TABLE[g5 ^ k_bytes[3]] ^ g6
    g3 = F_TABLE[g4 ^ k_bytes[2]] ^ g5
    g2 = F_TABLE[g3 ^ k_bytes[1]] ^ g4
    g1 = F_TABLE[g2 ^ k_bytes[0]] ^ g3
    return (g1 << 8) | g2


def get_round_keys(key: bytes, round_idx: int) -> list[int]:
    if len(key) != 10:
        raise ValueError("A chave Skipjack deve possuir exatamente 10 bytes (80 bits).")

    if not 1 <= round_idx <= 32:
        raise ValueError("O índice da rodada deve estar entre 1 e 32.")

    return [key[(4 * (round_idx - 1) + j) % 10] for j in range(4)]


def skipjack_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """Cifra um único bloco de 64 bits (8 bytes) com chave de 80 bits (10 bytes)."""

    if len(plaintext) != 8:
        raise ValueError("O bloco de texto claro deve possuir exatamente 8 bytes.")

    if len(key) != 10:
        raise ValueError("A chave Skipjack deve possuir exatamente 10 bytes.")

    w1, w2, w3, w4 = struct.unpack('>4H', plaintext)

    for i in range(1, 33):
        k_bytes = get_round_keys(key, i)

        if (1 <= i <= 8) or (17 <= i <= 24):
            gw = permute_G(w1, k_bytes)
            new_w1 = gw ^ w4 ^ i
            new_w2 = gw
            new_w3 = w2
            new_w4 = w3
        else:
            gw = permute_G(w1, k_bytes)
            new_w1 = w4
            new_w2 = gw
            new_w3 = w1 ^ w2 ^ i
            new_w4 = w3

        w1, w2, w3, w4 = new_w1, new_w2, new_w3, new_w4

    return struct.pack('>4H', w1, w2, w3, w4)


def skipjack_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """Decifra um único bloco de 64 bits (8 bytes) com chave de 80 bits (10 bytes)."""

    if len(ciphertext) != 8:
        raise ValueError("O bloco cifrado deve possuir exatamente 8 bytes.")

    if len(key) != 10:
        raise ValueError("A chave Skipjack deve possuir exatamente 10 bytes.")

    w1, w2, w3, w4 = struct.unpack('>4H', ciphertext)

    for i in range(32, 0, -1):
        k_bytes = get_round_keys(key, i)

        if (1 <= i <= 8) or (17 <= i <= 24):
            prev_w1 = inverse_permute_G(w2, k_bytes)
            prev_w2 = w3
            prev_w3 = w4
            prev_w4 = w1 ^ w2 ^ i
        else:
            prev_w1 = inverse_permute_G(w2, k_bytes)
            prev_w2 = prev_w1 ^ w3 ^ i
            prev_w3 = w4
            prev_w4 = w1

        w1, w2, w3, w4 = prev_w1, prev_w2, prev_w3, prev_w4

    return struct.pack('>4H', w1, w2, w3, w4)


# --- Padding PKCS#7 para blocos de 8 bytes (64 bits) ---

def pad_pkcs7(data: bytes, block_size: int = 8) -> bytes:
    if not 1 <= block_size <= 255:
        raise ValueError("Tamanho de bloco inválido.")

    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def unpad_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % 8 != 0:
        raise ValueError("Dados inválidos para remoção do padding.")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > 8:
        raise ValueError("Padding inválido ou chave incorreta.")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 inválido.")

    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Os dados devem possuir o mesmo tamanho para XOR.")

    return bytes(x ^ y for x, y in zip(a, b))


# --- Modos de Operação: ECB e CBC ---

def encrypt_ecb(data: bytes, key: bytes) -> bytes:
    if len(key) != 10:
        raise ValueError("A chave Skipjack deve possuir exatamente 10 bytes.")

    padded = pad_pkcs7(data)
    out = bytearray()

    for i in range(0, len(padded), 8):
        out.extend(skipjack_encrypt_block(padded[i:i+8], key))

    return bytes(out)


def decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 10:
        raise ValueError("A chave Skipjack deve possuir exatamente 10 bytes.")

    if not ciphertext or len(ciphertext) % 8 != 0:
        raise ValueError("O texto cifrado deve possuir blocos completos de 8 bytes.")

    out = bytearray()

    for i in range(0, len(ciphertext), 8):
        out.extend(skipjack_decrypt_block(ciphertext[i:i+8], key))

    return unpad_pkcs7(bytes(out))


def encrypt_cbc(data: bytes, key: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
    if len(key) != 10:
        raise ValueError("A chave Skipjack deve possuir exatamente 10 bytes.")

    if iv is None:
        iv = secrets.token_bytes(8)

    if len(iv) != 8:
        raise ValueError("O IV deve possuir exatamente 8 bytes (64 bits).")

    padded = pad_pkcs7(data)
    out = bytearray()
    prev_block = iv

    for i in range(0, len(padded), 8):
        block = xor_bytes(padded[i:i+8], prev_block)
        enc_block = skipjack_encrypt_block(block, key)
        out.extend(enc_block)
        prev_block = enc_block

    return iv, bytes(out)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 10:
        raise ValueError("A chave Skipjack deve possuir exatamente 10 bytes.")

    if len(iv) != 8:
        raise ValueError("O IV deve possuir exatamente 8 bytes (64 bits).")

    if not ciphertext or len(ciphertext) % 8 != 0:
        raise ValueError("O texto cifrado deve possuir blocos completos de 8 bytes.")

    out = bytearray()
    prev_block = iv

    for i in range(0, len(ciphertext), 8):
        enc_block = ciphertext[i:i+8]
        dec_block = skipjack_decrypt_block(enc_block, key)
        out.extend(xor_bytes(dec_block, prev_block))
        prev_block = enc_block

    return unpad_pkcs7(bytes(out))


# --- Validação Oficial (Vetor de Teste do NIST - 1998) ---

def validar_vetor_nist() -> bool:
    chave_nist = bytes.fromhex("00998877665544332211")
    entrada_nist = bytes.fromhex("33221100ddccbbaa")
    esperado_nist = bytes.fromhex("2587cae27a12d300")

    cifrado = skipjack_encrypt_block(entrada_nist, chave_nist)
    decifrado = skipjack_decrypt_block(cifrado, chave_nist)

    return (cifrado == esperado_nist) and (decifrado == entrada_nist)
