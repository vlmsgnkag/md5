from flask import Flask, request, render_template
import hashlib
import base64
import hmac
import zlib
import os

app = Flask(__name__)

# --- Hàm MD5 nâng cao ---
def md5_hash(input_str, iterations=10, salt="bigSmallMD5"):
    """
    Hàm băm MD5 nâng cao:
    - Ghép salt vào chuỗi đầu vào
    - Thực hiện MD5 theo nhiều vòng lặp để “tinh chỉnh” kết quả
    """
    combined = input_str + salt
    result = hashlib.md5(combined.encode('utf-8')).hexdigest()
    for i in range(iterations):
        result = hashlib.md5(result.encode('utf-8')).hexdigest()
    return result

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

# --- Hàm tạo hash tổng hợp ---
def generate_hash(md5_input, salt="TAIXIU_2025"):
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
    custom_hash_murmur3  = custom_murmur3(md5_input)
    custom_hash_crc32    = custom_crc32(md5_input)
    
    # --- Các hàm băm tự chế "xịn" mới ---
    custom_hash_xor_shift = custom_xor_shift_hash(md5_input)
    custom_hash_chaos     = custom_chaos_hash(md5_input)
    custom_hash_bitmix    = custom_bitmix_hash(md5_input)
    
    # --- Kết hợp tất cả các giá trị hash (nối thành chuỗi) ---
    hash_list = [
        md5_input, sha256, sha3_256, blake2b, sha512, blake2s, sha1, sha384,
        sha3_512, sha224, sha3_224, sha3_384, blake2b_512, blake2b_256,
        md5_single, md5_double, md5_triple, md5_quadruple, md5_quintuple,
        sha512_md5, sha256_blake2b, sha3_mix,
        shake_128, shake_256, sha512_224, sha512_256,
        extra_hash1, extra_hash2, extra_hash3, extra_hash4, extra_hash5,
        extra_hash6, extra_hash7, extra_hash8, extra_hash9, extra_hash10,
        extra_hash11, extra_hash12, extra_hash13, extra_hash14,
        hmac_sha256, pbkdf2_sha256, scrypt_hash,
        base64_hash,
        custom_hash_djb2, custom_hash_sdbm,
        custom_hash_fnv1a, custom_hash_adler32,
        custom_hash_murmur3, custom_hash_crc32,
        custom_hash_xor_shift, custom_hash_chaos, custom_hash_bitmix
    ]
    combined_hash = "".join(hash_list)
    
    # Sử dụng hàm md5_hash nâng cao để “tinh chỉnh” kết quả với salt TAIXIU_MD5
    special_md5 = md5_hash(combined_hash, iterations=10, salt="TAIXIU_MD5")
    combined_hash += special_md5  # Kết hợp thêm kết quả md5_hash đặc biệt
    
    # Tạo final_hash với vòng lặp mix bổ sung
    final_hash = hashlib.md5(combined_hash.encode('utf-8')).hexdigest()
    for i in range(10):
        final_hash = hashlib.sha256(final_hash.encode('utf-8')).hexdigest()
    for i in range(5):
        final_hash = hashlib.md5(final_hash.encode('utf-8')).hexdigest()
    
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

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None
    input_data = ""
    final_hash = ""
    hash_details = {}
    win_rate = None
    if request.method == 'POST':
        input_data = request.form['input_data']
        final_hash, hash_details = generate_hash(input_data)
        prediction = predict_tai_xiu(final_hash)
        win_rate = calculate_win_rate(final_hash)
    return render_template('index.html', prediction=prediction, input_data=input_data, final_hash=final_hash, hash_details=hash_details, win_rate=win_rate)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
