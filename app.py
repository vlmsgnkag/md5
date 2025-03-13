import time
from flask import Flask, request, render_template
import hashlib
import base64
import hmac
import re
import zlib
import secrets
import os

app = Flask(__name__)

# --- Hàm MD5 nâng cao ---
def md5_hash(input_str, iterations=50, salt="TAIXIU_MD5"):
    """
    Hàm băm MD5 nâng cao:
    - Ghép salt vào chuỗi đầu vào
    - Thực hiện nhiều vòng trộn để “tinh chỉnh” kết quả
    """
    combined = input_str + salt
    parts = [
         custom_xor_shift_hash(combined),
         custom_chaos_hash(combined),
         custom_bitmix_hash(combined),
         custom_rotate_add_hash(combined),
         custom_prime_mix_hash(combined),
         custom_djb2(combined),
         custom_sdbm(combined),
         custom_fnv1a(combined),
         custom_adler32(combined),
         custom_murmur3(combined),
         custom_crc32(combined),
         custom_polynomial_hash(combined),
         custom_bkdr_hash(combined),
         custom_shift_mix_hash(combined),
         custom_feistel_hash(combined),
         custom_entropy_hash(combined),
         custom_rotational_mix_hash2(combined),
         custom_dynamic_prime_hash(combined),
         custom_fibonacci_hash(combined),
         custom_sin_cos_hash(combined),
         custom_arctan_hash(combined),
         custom_xor_rotate_mix_hash(combined),
         custom_fibonacci_chaos_hash(combined),
         custom_matrix_mix_hash(combined),
         custom_rsa_mod_hash(combined),
         custom_double_logistic_hash(combined)
    ]
    combined_hash = "".join(parts)
    result_bytes = bytearray(combined_hash.encode('utf-8'))
    for i in range(iterations):
        # Tạo salt phụ cho vòng lặp hiện tại
        iter_salt = bytearray((salt + str(i)).encode('utf-8'))
        if len(iter_salt) < len(result_bytes):
            multiplier = (len(result_bytes) // len(iter_salt)) + 1
            iter_salt = iter_salt * multiplier
        iter_salt = iter_salt[:len(result_bytes)]
        # Trộn bằng phép XOR
        result_bytes = bytearray(a ^ b for a, b in zip(result_bytes, iter_salt))
        # Xoay trái từng byte với offset thay đổi (1 đến 8)
        offset = (i % 8) + 1
        result_bytes = bytearray(((val << offset) | (val >> (8 - offset))) & 0xFF for val in result_bytes)
        # Cộng thêm offset modulo 256
        result_bytes = bytearray(((val + offset) % 256) for val in result_bytes)
        final_hash = result_bytes.hex()
        return final_hash


    result = hashlib.md5(combined.encode('utf-8')).digest()  # 16 bytes

    

    for i in range(iterations):
        # Bước 2: Tạo hai salt phụ từ MD5 và SHA256, kết hợp chúng
        salt_str = salt + str(i)
        salt_md5 = hashlib.md5(salt_str.encode('utf-8')).digest()       # 16 bytes
        salt_sha256 = hashlib.sha256(salt_str.encode('utf-8')).digest()   # 32 bytes, dùng 16 bytes đầu
        iter_salt = bytes(a ^ b for a, b in zip(salt_md5, salt_sha256[:16]))
        
        # Bước 3: XOR kết quả hiện tại với salt phụ (làm việc với bytes)
        mixed = bytes(a ^ b for a, b in zip(result, iter_salt))
        # Nối kết quả với salt phụ và băm lại bằng MD5
        combined_mix = mixed + iter_salt
        result = hashlib.md5(combined_mix).digest()
        
        # Bước 4: Xoay trái bit với offset thay đổi (offset từ 1 đến 7)
        int_val = int.from_bytes(result, 'big')
        offset = (i % 7) + 1  # offset từ 1 đến 7 bit
        int_val = ((int_val << offset) | (int_val >> (128 - offset))) & ((1 << 128) - 1)
        result = int_val.to_bytes(16, 'big')
        
        # Bước 5: Nếu vòng lặp là số chẵn, đảo ngược thứ tự các byte
        if i % 2 == 0:
            result = result[::-1]
        
        # Bước 6: Nhân kết quả với hằng số nguyên tố và modulo 2^128 để xáo trộn thêm
        int_val = int.from_bytes(result, 'big')
        int_val = (int_val * 0x9e3779b97f4a7c15) & ((1 << 128) - 1)
        result = int_val.to_bytes(16, 'big')
    
    return result.hex()

# --- Các hàm băm tự chế đã có ---
def custom_djb2(s):
    hash_val = 5381
    for c in s:
        hash_val = ((hash_val << 5) + hash_val) + ord(c)  # hash * 33 + ord(c)
    return hex(hash_val & 0xFFFFFFFFFFFFFFFF)[2:]

def custom_sdbm(s):
    hash_val = 0
    for c in s:
        hash_val = ord(c) + (hash_val << 6) + (hash_val << 16) - hash_val
    return hex(hash_val & 0xFFFFFFFFFFFFFFFF)[2:]

def custom_fnv1a(s):
    hash_val = 14695981039346656037
    fnv_prime = 1099511628211
    for byte in s.encode('utf-8'):
        hash_val ^= byte
        hash_val *= fnv_prime
        hash_val &= 0xFFFFFFFFFFFFFFFF
    return hex(hash_val)[2:]

def custom_adler32(s):
    a = 1
    b = 0
    MOD_ADLER = 65521
    for byte in s.encode('utf-8'):
        a = (a + byte) % MOD_ADLER
        b = (b + a) % MOD_ADLER
    result = (b << 16) | a
    return hex(result)[2:]

# --- Các hàm băm nâng cao tự chế đã có ---
def custom_murmur3(s, seed=0):
    key = bytearray(s.encode('utf-8'))
    length = len(key)
    nblocks = length // 4

    h = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for i in range(nblocks):
        k = key[i*4] | (key[i*4+1] << 8) | (key[i*4+2] << 16) | (key[i*4+3] << 24)
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> (32-15))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF

        h ^= k
        h = ((h << 13) | (h >> (32-13))) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail_index = nblocks * 4
    k = 0
    tail_size = length & 3
    if tail_size == 3:
        k |= key[tail_index+2] << 16
    if tail_size >= 2:
        k |= key[tail_index+1] << 8
    if tail_size >= 1:
        k |= key[tail_index]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> (32-15))) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k

    h ^= length
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)
    return hex(h)[2:]

def custom_crc32(s):
    crc = zlib.crc32(s.encode('utf-8')) & 0xffffffff
    return hex(crc)[2:]

# --- Các hàm băm tự chế "xịn" mới ---
def custom_xor_shift_hash(s):
    """
    Hàm băm sử dụng kỹ thuật XOR và bit-shift.
    """
    h = 0xA5A5A5A5A5A5A5A5
    for c in s:
        h ^= ord(c)
        # Thực hiện xoay trái 13 bit
        h = ((h << 13) | (h >> (64-13))) & 0xFFFFFFFFFFFFFFFF
        h *= 0x100000001B3  # sử dụng hằng số FNV prime (64-bit)
        h &= 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]

def custom_chaos_hash(s):
    """
    Hàm băm dựa trên logistic map (hàm hỗn loạn).
    """
    x = 0.5
    for c in s:
        x = 4 * x * (1 - x)  # logistic map
        x += ord(c) / 256.0
        x %= 1.0
    h = int(x * (2**64))
    return hex(h)[2:]

def custom_bitmix_hash(s):
    """
    Hàm băm sử dụng xoay bit và nhân với hằng số độc đáo.
    """
    h = 0xDEADBEEFCAFEBABE
    for c in s:
        h = ((h << 5) | (h >> (64-5))) & 0xFFFFFFFFFFFFFFFF
        h ^= ord(c)
        h *= 0x27d4eb2f165667c5
        h &= 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]

def custom_polynomial_hash(s, base=257, mod=(1 << 64) - 59):
    """
    Hàm băm theo đa thức (Polynomial Rolling Hash):
    - Sử dụng cơ số (base) và modulo (mod) để tính toán.
    - Công thức: hash = (hash * base + ord(c)) % mod cho mỗi ký tự.
    - Chọn base và mod sao cho kết quả có phạm vi lớn, tạo ra sự phân tán tốt.
    """
    h = 0
    for c in s:
        h = (h * base + ord(c)) % mod
    return hex(h)[2:]


def custom_rotate_add_hash(s):
    """
    Hàm băm sử dụng xoay bit và cộng dồn:
    - Bắt đầu với h = 0.
    - Với mỗi ký tự, xoay trái h 5 bit (trong không gian 64-bit) rồi cộng giá trị của ký tự.
    - Kết quả được giới hạn trong 64-bit.
    """
    h = 0
    for c in s:
        # Xoay trái 5 bit trong không gian 64-bit
        h = ((h << 5) | (h >> (64 - 5))) & 0xFFFFFFFFFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_prime_mix_hash(s):
    """
    Hàm băm kết hợp với các số nguyên tố:
    - Duyệt từng ký tự của chuỗi và nhân giá trị hash với một số nguyên tố thay đổi theo vị trí.
    - Các số nguyên tố được lấy từ một danh sách cố định để tạo sự “xáo trộn” và phân tán.
    - Kết quả được giới hạn trong 64-bit.
    """
    primes = [31, 37, 41, 43, 47, 53, 59, 61]  # Danh sách các số nguyên tố nhỏ
    h = 0
    for i, c in enumerate(s):
        prime = primes[i % len(primes)]
        h = (h * prime + ord(c)) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]

def custom_bkdr_hash(s):
    """
    BKDR Hash sử dụng cơ số 131 với bước avalanche bổ sung.
    """
    hash_val = 0
    seed = 131
    for c in s:
        hash_val = (hash_val * seed + ord(c)) & 0xFFFFFFFFFFFFFFFF
    hash_val ^= (hash_val >> 13)
    hash_val = (hash_val * 0x5bd1e995) & 0xFFFFFFFFFFFFFFFF
    hash_val ^= (hash_val >> 15)
    return hex(hash_val)[2:]


def custom_shift_mix_hash(s):
    """
    Hàm băm kết hợp phép dịch bit và cộng với hằng số golden ratio.
    """
    h = 0xABCDEF1234567890
    for c in s:
        h ^= ord(c)
        h = ((h << 7) | (h >> (64-7))) & 0xFFFFFFFFFFFFFFFF
        h = (h + 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
        h ^= (h >> 3)
    return hex(h)[2:]


def custom_feistel_hash(s):
    """
    Hàm băm kiểu Feistel network:
    - Chia chuỗi thành hai nửa, sau đó thực hiện 4 vòng Feistel để trộn lẫn dữ liệu.
    """
    if len(s) % 2 != 0:
        s += s[-1]
    mid = len(s) // 2
    left = [ord(c) for c in s[:mid]]
    right = [ord(c) for c in s[mid:]]
    rounds = 4
    for _ in range(rounds):
        new_right = []
        for i in range(len(right)):
            # Hàm F đơn giản: kết hợp nhân và dịch bit
            f = ((right[i] * 0x45d9f3b) & 0xFFFFFFFF) ^ (right[i] >> 3)
            new_val = left[i] ^ f
            new_right.append(new_val & 0xFF)
        left, right = right, new_right
    combined = left + right
    result = 0
    for val in combined:
        result = ((result << 8) | val) & 0xFFFFFFFFFFFFFFFF
    result ^= (result >> 33)
    result = (result * 0xff51afd7ed558ccd) & 0xFFFFFFFFFFFFFFFF
    result ^= (result >> 33)
    return hex(result)[2:]

def custom_entropy_hash(s):
    """
    Hàm băm dựa trên sự pha trộn của hàm lượng giác để tạo “entropy”:
    - Sử dụng sin, cos của các giá trị kết hợp với chỉ số để tạo giá trị số học lớn.
    """
    import math
    h = 0xABCDEF1234567890
    for i, c in enumerate(s):
        # Sử dụng sin và cos tạo giá trị dao động, cộng thêm offset theo index
        value = math.sin(ord(c) + i) + math.cos(ord(c) * (i + 1))
        # Chuyển đổi thành số nguyên sau khi scale (đảm bảo dương bằng cách cộng 2)
        h ^= int((value + 2) * 1000000)
        # Xoay trái theo offset phụ thuộc vào vị trí
        offset = (i % 16) + 1
        h = ((h << offset) | (h >> (64 - offset))) & 0xFFFFFFFFFFFFFFFF
        h = (h * 0x9e3779b97f4a7c15) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 31)
    return hex(h)[2:]

def custom_rotational_mix_hash2(s):
    """
    Hàm băm sử dụng xoay bit với offset thay đổi theo index và cộng dồn:
    - Sử dụng hằng số khác với custom_rotate_add_hash để tăng sự khác biệt.\n
    """
    h = 0xFEDCBA9876543210
    for i, c in enumerate(s):
        offset = (i % 7) + 1
        h = ((h << offset) | (h >> (64 - offset))) & 0xFFFFFFFFFFFFFFFF
        h ^= (ord(c) * (i + 1))
        h = (h + 0xC6A4A7935BD1E995) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 27)
    return hex(h)[2:]

def custom_dynamic_prime_hash(s):
    """
    Hàm băm sử dụng dãy số nguyên tố động:
    - Sử dụng một dãy số nguyên tố cố định, thay đổi theo index, và kết hợp với phép XOR.\n
    """
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
    h = 1
    for i, c in enumerate(s):
        prime = primes[i % len(primes)]
        h = (h * prime + ord(c) * prime) & 0xFFFFFFFFFFFFFFFF
        h ^= (h >> 5)
    h ^= (h << 3) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_fibonacci_chaos_hash(s):
    """
    Kết hợp dãy Fibonacci và logistic chaos:
    - Dãy Fibonacci tạo biến đổi số học, kết hợp với logistic map cho tính hỗn loạn.
    """
    import math
    fib_a, fib_b = 1, 1
    x = 0.7
    h = 0
    for c in s:
        fib_a, fib_b = fib_b, (fib_a + fib_b) % 1000003
        x = 3.99 * x * (1 - x)
        h ^= (ord(c) * fib_b + int(x * 1000000)) & 0xFFFFFFFFFFFFFFFF
        h = ((h << 3) | (h >> (64 - 3))) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_matrix_mix_hash(s):
    """
    Sử dụng phép nhân ma trận 2x2 cho từng block của chuỗi:
    - Chia chuỗi thành block 4 ký tự, pad nếu cần.
    - Mỗi block chuyển thành vector và nhân với ma trận cố định.
    """
    M = [[3, 5], [7, 11]]  # Ma trận 2x2 với số nguyên tố nhỏ
    h = 0
    for i in range(0, len(s), 4):
        block = s[i:i+4]
        if len(block) < 4:
            block = block.ljust(4, '0')
        v1 = sum(ord(c) << (8 * (j % 4)) for j, c in enumerate(block[:2]))
        v2 = sum(ord(c) << (8 * (j % 4)) for j, c in enumerate(block[2:]))
        new_v1 = (M[0][0] * v1 + M[0][1] * v2) & 0xFFFFFFFF
        new_v2 = (M[1][0] * v1 + M[1][1] * v2) & 0xFFFFFFFF
        h ^= (new_v1 << 16) | new_v2
        h = ((h << 5) | (h >> (32 - 5))) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_rsa_mod_hash(s):
    """
    Mô phỏng nguyên lý RSA:
    - Sử dụng số nguyên tố lớn cố định làm modulo.
    - Với mỗi ký tự, tính lũy thừa modulo dựa trên giá trị ký tự và vị trí.
    """
    prime_mod = 4294967311  # Số nguyên tố gần 2^32
    h = 1
    for i, c in enumerate(s):
        exponent = (i + ord(c)) % 13 + 2
        h = pow(h * (ord(c) + 1), exponent, prime_mod)
    return hex(h)[2:]


def custom_double_logistic_hash(s):
    """
    Áp dụng logistic map hai lần với các tham số khác nhau:
    - Lần đầu với 3.98, lần thứ hai với 3.97.
    - Kết hợp hai kết quả để tăng tính hỗn loạn.
    """
    x1 = 0.6
    x2 = 0.7
    h = 0
    for i, c in enumerate(s):
        x1 = 3.98 * x1 * (1 - x1)
        x2 = 3.97 * x2 * (1 - x2)
        combined = int((x1 + x2) * 500000)
        h ^= (ord(c) + combined + i) & 0xFFFFFFFFFFFFFFFF
        h = ((h << 4) | (h >> (64 - 4))) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_fibonacci_hash(s):
    fib_a, fib_b = 0, 1
    h = 0
    for c in s:
        fib_a, fib_b = fib_b, (fib_a + fib_b) % 1000003
        h = (h * 31 + ord(c) + (fib_b % 100)) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_sin_cos_hash(s):
    import math
    h = 0
    for i, c in enumerate(s):
        part = int(math.sin(ord(c) + i) * 1000) ^ int(math.cos(ord(c) * (i + 1)) * 1000)
        h ^= part
        h = ((h << 3) | (h >> (64 - 3))) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_arctan_hash(s):
    import math
    h = 0
    for i, c in enumerate(s):
        h += int(math.atan(ord(c) + i) * 1000000)
        h &= 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]


def custom_xor_rotate_mix_hash(s):
    h = 0xCAFEBABEDEADBEEF
    for i, c in enumerate(s):
        h ^= ord(c) * (i + 1)
        offset = (h % 13) + 1
        h = ((h << offset) | (h >> (64 - offset))) & 0xFFFFFFFFFFFFFFFF
        h = (h * 0xA5A5A5A5A5A5A5A5) & 0xFFFFFFFFFFFFFFFF
    return hex(h)[2:]



# --- Hàm tạo hash tổng hợp ---
def generate_hash(md5_input, salt="TAIXIU_MD5", mode="ultra"):
    # Nếu đầu vào khớp định dạng MD5 (32 ký tự hex) thì tăng cường xử lý
    if re.fullmatch(r'[a-fA-F0-9]{32}', md5_input):
        iterations = 100
        enhanced_salt = salt + "_ENHANCED"
        md5_input = md5_hash(md5_input, iterations=iterations, salt=enhanced_salt)
    else:
        iterations = 50
        enhanced_salt = salt

    # Lấy pepper từ biến môi trường (nếu không có, dùng mặc định)
    pepper = os.environ.get("HASH_PEPPER", "DEFAULT_PEPPER")
    # Yếu tố thời gian: nano giây hiện tại
    time_factor = str(time.time_ns())
    # Tạo random salt (16 byte dưới dạng hex)
    random_salt = secrets.token_hex(16)
    # Kết hợp các yếu tố để tạo final_salt
    final_salt = enhanced_salt + pepper + time_factor + random_salt

    # Các hàm băm chuẩn từ module hashlib
    sha256         = hashlib.sha256(md5_input.encode('utf-8')).hexdigest()
    sha3_256       = hashlib.sha3_256(md5_input.encode('utf-8')).hexdigest()
    blake2b        = hashlib.blake2b(md5_input.encode('utf-8')).hexdigest()
    sha512         = hashlib.sha512(md5_input.encode('utf-8')).hexdigest()
    blake2s        = hashlib.blake2s(md5_input.encode('utf-8')).hexdigest()
    sha1           = hashlib.sha1(md5_input.encode('utf-8')).hexdigest()
    sha384         = hashlib.sha384(md5_input.encode('utf-8')).hexdigest()
    sha3_512       = hashlib.sha3_512(md5_input.encode('utf-8')).hexdigest()
    sha224         = hashlib.sha224(md5_input.encode('utf-8')).hexdigest()
    sha3_224       = hashlib.sha3_224(md5_input.encode('utf-8')).hexdigest()
    sha3_384       = hashlib.sha3_384(md5_input.encode('utf-8')).hexdigest()
    blake2b_512    = hashlib.blake2b(md5_input.encode('utf-8'), digest_size=64).hexdigest()
    blake2b_256    = hashlib.blake2b(md5_input.encode('utf-8'), digest_size=32).hexdigest()
    
    # Biến thể MD5 theo chuỗi cải tiến
    md5_single     = hashlib.md5(md5_input.encode('utf-8')).hexdigest()
    md5_double     = hashlib.md5(md5_single.encode('utf-8')).hexdigest()
    md5_triple     = hashlib.md5(md5_double.encode('utf-8')).hexdigest()
    md5_quadruple  = hashlib.md5(md5_triple.encode('utf-8')).hexdigest()
    md5_quintuple  = hashlib.md5(md5_quadruple.encode('utf-8')).hexdigest()
    
    sha512_md5     = hashlib.sha512(md5_input.encode('utf-8')).hexdigest()
    sha256_blake2b = hashlib.sha256(blake2b.encode('utf-8')).hexdigest()
    sha3_mix       = hashlib.sha3_512((sha256 + sha3_256 + sha1).encode('utf-8')).hexdigest()
    
    # Shake với đầu ra cố định
    shake_128      = hashlib.shake_128(md5_input.encode('utf-8')).hexdigest(16)
    shake_256      = hashlib.shake_256(md5_input.encode('utf-8')).hexdigest(32)
    
    # Mô phỏng SHA512-224 và SHA512-256 từ SHA-512
    sha512_224     = sha512[:56]
    sha512_256     = sha512[:64]
    
    # Các hàm băm phụ trợ (Extra Hashes)
    extra_hash1  = hashlib.sha256((sha256 + sha3_256 + sha1).encode('utf-8')).hexdigest()
    extra_hash2  = hashlib.sha512((blake2b + sha512 + sha384).encode('utf-8')).hexdigest()
    extra_hash3  = hashlib.md5((blake2s + sha1 + md5_input).encode('utf-8')).hexdigest()
    extra_hash4  = hashlib.sha3_512((sha256 + blake2b).encode('utf-8')).hexdigest()
    extra_hash5  = hashlib.blake2s((sha512 + sha3_256).encode('utf-8')).hexdigest()
    extra_hash6  = hashlib.sha3_256((sha224 + sha3_224).encode('utf-8')).hexdigest()
    extra_hash7  = hashlib.sha3_384((sha3_512 + blake2b_512).encode('utf-8')).hexdigest()
    extra_hash8  = hashlib.sha256((extra_hash1 + extra_hash2).encode('utf-8')).hexdigest()
    extra_hash9  = hashlib.md5((sha1 + shake_128 + extra_hash3).encode('utf-8')).hexdigest()
    extra_hash10 = hashlib.sha3_256((sha256 + sha384 + sha512).encode('utf-8')).hexdigest()
    extra_hash11 = hashlib.sha256((extra_hash8 + extra_hash9).encode('utf-8')).hexdigest()
    extra_hash12 = hashlib.sha3_384((extra_hash10 + sha256_blake2b).encode('utf-8')).hexdigest()
    extra_hash13 = hashlib.sha256((md5_single + sha3_mix).encode('utf-8')).hexdigest()
    extra_hash14 = hashlib.sha3_512((shake_128 + shake_256).encode('utf-8')).hexdigest()
    
    # Các hàm băm nâng cao từ module
    hmac_sha256    = hmac.new(salt.encode('utf-8'), md5_input.encode('utf-8'), hashlib.sha256).hexdigest()
    pbkdf2_sha256  = hashlib.pbkdf2_hmac('sha256', md5_input.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    scrypt_hash    = hashlib.scrypt(md5_input.encode('utf-8'), salt=salt.encode('utf-8'), n=16384, r=8, p=1, dklen=64).hex()
    
    # Base64 của đầu vào
    base64_hash = base64.b64encode(md5_input.encode('utf-8')).decode('utf-8')
    
    # Các hàm băm tự chế đã có và nâng cao mới
    custom_hash_djb2     = custom_djb2(md5_input)
    custom_hash_sdbm     = custom_sdbm(md5_input)
    custom_hash_fnv1a    = custom_fnv1a(md5_input)
    custom_hash_adler32  = custom_adler32(md5_input)
    custom_polynomial_hash  = custom_adler32(md5_input)
    custom_rotate_add_hash  = custom_adler32(md5_input)
    custom_prime_mix_hash  = custom_adler32(md5_input)
    custom_hash_murmur3  = custom_murmur3(md5_input)
    custom_hash_crc32    = custom_crc32(md5_input)
    hash_fibonacci = custom_fibonacci_hash(md5_input)
    hash_sin_cos = custom_sin_cos_hash(md5_input)
    hash_arctan = custom_arctan_hash(md5_input)
    hash_xor_rotate_mix = custom_xor_rotate_mix_hash(md5_input)
    hash_fib_chaos = custom_fibonacci_chaos_hash(md5_input)
    hash_matrix_mix = custom_matrix_mix_hash(md5_input)
    hash_rsa_mod = custom_rsa_mod_hash(md5_input)
    hash_double_logistic = custom_double_logistic_hash(md5_input)
    
    # --- Các hàm băm tự chế "xịn" mới ---
    custom_hash_xor_shift = custom_xor_shift_hash(md5_input)
    custom_hash_chaos     = custom_chaos_hash(md5_input)
    custom_hash_bkdr      = custom_bkdr_hash(md5_input)
    custom_hash_shift_mix = custom_shift_mix_hash(md5_input)
    custom_hash_feistel   = custom_feistel_hash(md5_input)
    custom_entropy         = custom_entropy_hash(md5_input)
    custom_rot_mix2        = custom_rotational_mix_hash2(md5_input)
    custom_dyn_prime       = custom_dynamic_prime_hash(md5_input)
    custom_hash_bitmix    = custom_bitmix_hash(md5_input)
    
    # --- Kết hợp tất cả các giá trị hash (nối thành chuỗi) ---
    hash_list = [
        md5_input, sha256, sha3_256, blake2b, sha512, blake2s, sha1, sha384,
        sha3_512, sha224, sha3_224, sha3_384, blake2b_512, blake2b_256,
        md5_single, md5_double, md5_triple, md5_quadruple, md5_quintuple,
        sha512_md5, custom_prime_mix_hash, sha256_blake2b, sha3_mix,
        shake_128, shake_256, sha512_224, sha512_256,
        extra_hash1, extra_hash2, extra_hash3, extra_hash4, extra_hash5,
        extra_hash6, extra_hash7, extra_hash8, extra_hash9, extra_hash10,
        extra_hash11, extra_hash12, extra_hash13, extra_hash14,
        hmac_sha256, pbkdf2_sha256, scrypt_hash, custom_hash_feistel,
        base64_hash, custom_hash_bkdr, custom_hash_shift_mix,
        custom_hash_djb2, custom_hash_sdbm,
        custom_hash_fnv1a, custom_hash_adler32, custom_dyn_prime,
        hash_fibonacci, hash_sin_cos, hash_arctan, hash_xor_rotate_mix,
        hash_fib_chaos, hash_matrix_mix, hash_rsa_mod, hash_double_logistic,
        custom_rot_mix2, custom_entropy,
        custom_hash_murmur3, custom_hash_crc32,
        custom_hash_xor_shift, custom_hash_chaos, custom_hash_bitmix, custom_rotate_add_hash, 
        custom_polynomial_hash
    ]
    combined_hash = "".join(hash_list)
    
    # Sử dụng hàm md5_hash nâng cao để “tinh chỉnh” kết quả với salt TAIXIU_MD5
    special_md5 = md5_hash(combined_hash, iterations=iterations, salt=enhanced_salt)
    combined_hash += special_md5  # Kết hợp thêm kết quả md5_hash đặc biệt
    
    # Tạo final_hash với vòng lặp mix bổ sung
    final_hash = hashlib.md5(combined_hash.encode('utf-8')).hexdigest()
    for i in range(10):
        final_hash = hashlib.sha256(final_hash.encode('utf-8')).hexdigest()
    for i in range(5):
        final_hash = hashlib.md5(final_hash.encode('utf-8')).hexdigest()
    
    # Sử dụng final_salt (đã được tính từ enhanced_salt, pepper, time_factor và random_salt)
    final_hash = hashlib.pbkdf2_hmac('sha512', final_hash.encode('utf-8'),
                                     final_salt.encode('utf-8'), 100000).hex()
    final_hash = hashlib.sha3_512(final_hash.encode('utf-8')).hexdigest()
    
    hash_details = {
        "MD5 Input": md5_input,
        "Salt": salt,
        "SHA-256": sha256,
        "SHA3-256": sha3_256,
        "BLAKE2b": blake2b,
        "SHA-512": sha512,
        "BLAKE2s": blake2s,
        "SHA-1": sha1,
        "SHA-384": sha384,
        "SHA3-512": sha3_512,
        "SHA-224": sha224,
        "SHA3-224": sha3_224,
        "SHA3-384": sha3_384,
        "BLAKE2b-512": blake2b_512,
        "BLAKE2b-256": blake2b_256,
        "MD5 Single": md5_single,
        "MD5 Double": md5_double,
        "MD5 Triple": md5_triple,
        "MD5 Quadruple": md5_quadruple,
        "MD5 Quintuple": md5_quintuple,
        "SHA512-MD5": sha512_md5,
        "SHA256-BLAKE2b": sha256_blake2b,
        "SHA3 Mix": sha3_mix,
        "SHAKE-128": shake_128,
        "SHAKE-256": shake_256,
        "SHA512-224 (simulated)": sha512_224,
        "SHA512-256 (simulated)": sha512_256,
        "Extra Hash 1": extra_hash1,
        "Extra Hash 2": extra_hash2,
        "Extra Hash 3": extra_hash3,
        "Extra Hash 4": extra_hash4,
        "Extra Hash 5": extra_hash5,
        "Extra Hash 6": extra_hash6,
        "Extra Hash 7": extra_hash7,
        "Extra Hash 8": extra_hash8,
        "Extra Hash 9": extra_hash9,
        "Extra Hash 10": extra_hash10,
        "Extra Hash 11": extra_hash11,
        "Extra Hash 12": extra_hash12,
        "Extra Hash 13": extra_hash13,
        "Extra Hash 14": extra_hash14,
        "HMAC-SHA256": hmac_sha256,
        "PBKDF2-HMAC-SHA256": pbkdf2_sha256,
        "Scrypt": scrypt_hash,
        "Base64 Encoding": base64_hash,
        "Custom DJB2": custom_hash_djb2,
        "Custom SDBM": custom_hash_sdbm,
        "Custom FNV-1a": custom_hash_fnv1a,
        "Custom Adler-32": custom_hash_adler32,
        "Custom Murmur3": custom_hash_murmur3,
        "Custom CRC32": custom_hash_crc32,
        "Custom XOR-Shift": custom_hash_xor_shift,
        "Custom Chaos": custom_hash_chaos,
        "Custom Bitmix": custom_hash_bitmix,
        "Custom Polynomial": custom_polynomial_hash,
        "Custom Rotate-Add": custom_rotate_add_hash,
        "Custom Prime Mix": custom_prime_mix_hash,
        "Special MD5": special_md5,
        "Final Hash": final_hash
    }
    return final_hash, hash_details

def predict_tai_xiu(final_hash):
    # Dự đoán Tài/Xỉu dựa trên tổng các ký tự hex của final_hash (cho kết quả trong khoảng 3-18)
    hex_digits = [int(c, 16) for c in final_hash]
    total = sum(hex_digits) % 16 + 3
    return "Tài" if total >= 11 else "Xỉu"

def calculate_win_rate(final_hash):
    win_rate = int(final_hash, 16) % 101
    return win_rate


# --- Chức năng so sánh hash của dãy số 3 tới 18 ---
def similarity_ratio(hash1, hash2):
    """
    Tính tỷ lệ trùng khớp giữa 2 chuỗi hash (theo từng ký tự so sánh vị trí).
    Kết quả là số thực từ 0 đến 1.
    """
    matches = sum(1 for a, b in zip(hash1, hash2) if a == b)
    ratio = matches / min(len(hash1), len(hash2))
    return ratio

def predict_with_range(final_hash):
    best_ratio = 0.0
    best_candidates = []  # Danh sách chứa tất cả các số đạt tỷ lệ tương đồng tốt nhất
    candidate_hashes = {}
    for num in range(3, 19):
        candidate_hash, candidate_details = generate_hash(str(num))
        ratio = similarity_ratio(final_hash, candidate_hash)
        # Lưu cả giá trị float và chuỗi định dạng (có dấu %)
        candidate_hashes[str(num)] = {
            "hash": candidate_hash,
            "details": candidate_details,
            "similarity": ratio,  # Giá trị float (0 đến 1)
            "similarity_str": f"{ratio * 100:.2f}%"  # Chuỗi định dạng
        }
        if ratio > best_ratio:
            best_ratio = ratio
            best_candidates = [num]
        elif ratio == best_ratio:
            best_candidates.append(num)
            
    # Dự đoán dựa trên trung bình của các số đạt tỷ lệ tốt nhất
    avg_candidate = sum(best_candidates) / len(best_candidates)
    prediction = "Xỉu" if avg_candidate <= 10 else "Tài"
    best_ratio_percent = f"{best_ratio * 100:.2f}%"
    return best_candidates, best_ratio_percent, prediction, candidate_hashes

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None
    input_data = ""
    final_hash = ""
    hash_details = {}
    win_rate = None
    range_result = {}
    if request.method == 'POST':
        input_data = request.form['input_data']
        final_hash, hash_details = generate_hash(input_data)
        prediction = predict_tai_xiu(final_hash)
        win_rate = calculate_win_rate(final_hash)
        best_candidate, best_ratio, range_prediction, candidate_hashes = predict_with_range(final_hash)
        range_result = {
            "Best Candidate": best_candidate,
            "Similarity Ratio": best_ratio,
            "Range Prediction": range_prediction,
            "Candidate Hashes": candidate_hashes
        }
    return render_template('index.html', prediction=prediction, input_data=input_data, final_hash=final_hash, hash_details=hash_details, win_rate=win_rate, range_result=range_result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
