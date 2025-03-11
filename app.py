from flask import Flask, request, render_template
import hashlib
import base64

app = Flask(__name__)

def generate_hash(md5_input):
    # Các hàm băm cơ bản
    sha256 = hashlib.sha256(md5_input.encode('utf-8')).hexdigest()
    sha3_256 = hashlib.sha3_256(md5_input.encode('utf-8')).hexdigest()
    blake2b = hashlib.blake2b(md5_input.encode('utf-8')).hexdigest()  # mặc định 512 bit
    sha512 = hashlib.sha512(md5_input.encode('utf-8')).hexdigest()
    blake2s = hashlib.blake2s(md5_input.encode('utf-8')).hexdigest()
    sha1 = hashlib.sha1(md5_input.encode('utf-8')).hexdigest()
    sha384 = hashlib.sha384(md5_input.encode('utf-8')).hexdigest()
    sha3_512 = hashlib.sha3_512(md5_input.encode('utf-8')).hexdigest()
    sha224 = hashlib.sha224(md5_input.encode('utf-8')).hexdigest()
    sha3_224 = hashlib.sha3_224(md5_input.encode('utf-8')).hexdigest()
    sha3_384 = hashlib.sha3_384(md5_input.encode('utf-8')).hexdigest()
    blake2b_512 = hashlib.blake2b(md5_input.encode('utf-8'), digest_size=64).hexdigest()
    blake2b_256 = hashlib.blake2b(md5_input.encode('utf-8'), digest_size=32).hexdigest()
    
    # Các biến thể MD5
    md5_double = hashlib.md5(md5_input.encode('utf-8')).hexdigest()
    md5_triple = hashlib.md5(md5_double.encode('utf-8')).hexdigest()
    sha512_md5 = hashlib.sha512(md5_input.encode('utf-8')).hexdigest()
    sha256_blake2b = hashlib.sha256(blake2b.encode('utf-8')).hexdigest()
    sha3_mix = hashlib.sha3_512((sha256 + sha3_256 + sha1).encode('utf-8')).hexdigest()
    
    # Shake (đầu ra cố định)
    shake_128 = hashlib.shake_128(md5_input.encode('utf-8')).hexdigest(16)
    shake_256 = hashlib.shake_256(md5_input.encode('utf-8')).hexdigest(32)
    
    # Mô phỏng SHA512-224 và SHA512-256 từ SHA-512
    sha512_224 = sha512[:56]  # 224 bit => 56 hex digits
    sha512_256 = sha512[:64]  # 256 bit => 64 hex digits
    
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
    
    # Base64 của đầu vào
    base64_hash = base64.b64encode(md5_input.encode('utf-8')).decode('utf-8')
    
    # Kết hợp tất cả các giá trị hash
    combined_hash = (md5_input + sha256 + sha3_256 + blake2b + sha512 + blake2s + sha1 + sha384 +
                     sha3_512 + sha224 + sha3_224 + sha3_384 + blake2b_512 + blake2b_256 +
                     md5_double + md5_triple + sha512_md5 + sha256_blake2b + sha3_mix +
                     shake_128 + shake_256 + sha512_224 + sha512_256 +
                     extra_hash1 + extra_hash2 + extra_hash3 + extra_hash4 + extra_hash5 +
                     extra_hash6 + extra_hash7 + extra_hash8 + extra_hash9 + extra_hash10 +
                     extra_hash11 + extra_hash12 + base64_hash)
    
    # Tạo final_hash qua MD5 của chuỗi kết hợp, sau đó thực hiện nhiều vòng lặp mix với SHA-256 và MD5
    final_hash = hashlib.md5(combined_hash.encode('utf-8')).hexdigest()
    for i in range(10):
        final_hash = hashlib.sha256(final_hash.encode('utf-8')).hexdigest()
    for i in range(5):
        final_hash = hashlib.md5(final_hash.encode('utf-8')).hexdigest()
    
    hash_details = {
        "MD5 Input": md5_input,
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
        "MD5 Double": md5_double,
        "MD5 Triple": md5_triple,
        "SHA-512 (MD5 Input)": sha512_md5,
        "SHA-256 (BLAKE2b)": sha256_blake2b,
        "SHA3 Mixed": sha3_mix,
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
        "Base64 Encoding": base64_hash,
        "Final Hash": final_hash
    }
    return final_hash, hash_details

def predict_tai_xiu(final_hash):
    # Sử dụng toàn bộ ký tự của final_hash để tính tổng, đưa về khoảng 3 đến 18
    hex_digits = [int(c, 16) for c in final_hash]
    total = sum(hex_digits) % 16 + 3
    return "Tài" if total >= 11 else "Xỉu"

@app.route('/', methods=['GET', 'POST'])
def index():
    prediction = None
    input_data = ""
    final_hash = ""
    hash_details = {}
    if request.method == 'POST':
        input_data = request.form['input_data']
        final_hash, hash_details = generate_hash(input_data)
        prediction = predict_tai_xiu(final_hash)
    return render_template('index.html', prediction=prediction, input_data=input_data, final_hash=final_hash, hash_details=hash_details)

if __name__ == '__main__':
    app.run(debug=True)
