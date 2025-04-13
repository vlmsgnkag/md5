#!/usr/bin/env python3
import logging
import sys
import math
import hashlib
import random
from decimal import Decimal, getcontext, ROUND_FLOOR
from statistics import mean

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ConversationHandler,
    ContextTypes,
    filters,
)

# Đặt độ chính xác cao cho các phép tính Decimal
getcontext().prec = 50

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Các trạng thái cho ConversationHandler của trò chơi Tài Xỉu
CAPITAL, TARGET, HASH_INPUT, RESULT = range(4)

# ---------------------------------------------------------------------------
# PHẦN 1: HÀM XỬ LÝ BẮN & TÍNH TOÁN CƠ BẢN
# ---------------------------------------------------------------------------
def validate_md5(md5_code: str) -> bool:
    """Kiểm tra mã MD5 hợp lệ (cần có 32 ký tự hex)."""
    print(f"Validating MD5: {md5_code}")
    if len(md5_code) != 32:
        print(f"Invalid length: {len(md5_code)}")
        return False
    try:
        int(md5_code, 16)
        return True
    except ValueError:
        print(f"Invalid character in MD5: {md5_code}")
        return False

def convert_hash_to_probability(hash_code: str) -> Decimal:
    """
    Chuyển đổi một chuỗi băm thành xác suất thuộc [0,1].
    Xác suất được tính theo: probability = integer_value / (16^(len(hash_code)) - 1).
    """
    integer_value = Decimal(int(hash_code, 16))
    max_integer = Decimal(16) ** Decimal(len(hash_code)) - Decimal(1)
    probability = integer_value / max_integer
    return probability

def compute_extended_bias(hash_code: str) -> Decimal:
    """
    Chia chuỗi băm thành 4 phần đều nhau và tính bias cho từng phần bằng hàm logistic mềm dần.
    
    Hàm logistic: L = L_max / (1 + exp(-k*(x - x0)))
      - L_max = 0.1, k = 10, x0 = 0.5
    Các ký tự được chuyển từ hexa (0–15) và chuẩn hóa về x trong [0,1].
    Trả về trung bình bias của các nhóm.
    """
    n = len(hash_code)
    num_groups = 4
    group_length = n // num_groups
    biases = []
    for i in range(num_groups):
        group = hash_code[i*group_length:(i+1)*group_length]
        group_bias = Decimal(0)
        for ch in group:
            normalized = int(ch, 16) / 15.0
            exp_val = Decimal(math.exp(-10 * (normalized - 0.5)))
            L = Decimal("0.1") / (Decimal(1) + exp_val)
            group_bias += L
        group_bias /= Decimal(len(group))
        biases.append(group_bias)
    avg_bias = sum(biases) / Decimal(len(biases))
    return avg_bias

def parse_hash_to_factor(hash_code: str) -> Decimal:
    """
    Tính hệ số cược từ chữ số cuối của số nguyên chuyển đổi từ chuỗi băm.
    Công thức: factor = 0.01 + (last_digit / 9) * 0.49.
    Nếu có lỗi thì trả về factor mặc định 0.05.
    """
    try:
        integer_value = int(hash_code, 16)
        last_digit = int(str(integer_value)[-1])
        factor = Decimal("0.01") + (Decimal(last_digit) / Decimal("9")) * Decimal("0.49")
        return factor
    except Exception:
        return Decimal("0.05")

# ---------------------------------------------------------------------------
# PHẦN 2: TÍNH TOÁN TRUNG BÌNH CỦA NHIỀU HÀM BĂM VÀ PHÂN TÍN PHÂN TÁN
# ---------------------------------------------------------------------------
def compute_multiple_probabilities(md5_code: str) -> dict:
    """
    Tính xác suất từ 6 hàm băm khác nhau: MD5, SHA-1, SHA-256, SHA3-256, BLAKE2b và SHA512.
    Trả về dict: { 'md5': prob_md5, 'sha1': prob_sha1, ... }
    """
    prob_md5 = convert_hash_to_probability(md5_code)
    sha1_code = hashlib.sha1(md5_code.encode()).hexdigest()
    prob_sha1 = convert_hash_to_probability(sha1_code)
    sha256_code = hashlib.sha256(md5_code.encode()).hexdigest()
    prob_sha256 = convert_hash_to_probability(sha256_code)
    sha3_code = hashlib.sha3_256(md5_code.encode()).hexdigest()
    prob_sha3 = convert_hash_to_probability(sha3_code)
    blake2b_code = hashlib.blake2b(md5_code.encode()).hexdigest()
    prob_blake2b = convert_hash_to_probability(blake2b_code)
    sha512_code = hashlib.sha512(md5_code.encode()).hexdigest()
    prob_sha512 = convert_hash_to_probability(sha512_code)
    return {
        'md5': prob_md5,
        'sha1': prob_sha1,
        'sha256': prob_sha256,
        'sha3': prob_sha3,
        'blake2b': prob_blake2b,
        'sha512': prob_sha512
    }

def compute_weighted_probability(md5_code: str) -> (Decimal, Decimal):
    """
    Tính trung bình xác suất và độ phân tán (variance) từ 6 hàm băm.
    """
    probs = compute_multiple_probabilities(md5_code)
    prob_values = list(probs.values())
    avg_probability = sum(prob_values) / Decimal(len(prob_values))
    mean_val = float(avg_probability)
    variance = sum((float(p) - mean_val) ** 2 for p in prob_values) / len(prob_values)
    return avg_probability, Decimal(variance)

def compute_multiple_biases(md5_code: str) -> dict:
    """
    Tính bias từ 6 hàm băm khác nhau dùng compute_extended_bias.
    """
    bias_md5 = compute_extended_bias(md5_code)
    sha1_code = hashlib.sha1(md5_code.encode()).hexdigest()
    bias_sha1 = compute_extended_bias(sha1_code)
    sha256_code = hashlib.sha256(md5_code.encode()).hexdigest()
    bias_sha256 = compute_extended_bias(sha256_code)
    sha3_code = hashlib.sha3_256(md5_code.encode()).hexdigest()
    bias_sha3 = compute_extended_bias(sha3_code)
    blake2b_code = hashlib.blake2b(md5_code.encode()).hexdigest()
    bias_blake2b = compute_extended_bias(blake2b_code)
    sha512_code = hashlib.sha512(md5_code.encode()).hexdigest()
    bias_sha512 = compute_extended_bias(sha512_code)
    return {
        'md5': bias_md5,
        'sha1': bias_sha1,
        'sha256': bias_sha256,
        'sha3': bias_sha3,
        'blake2b': bias_blake2b,
        'sha512': bias_sha512
    }

def compute_weighted_bias(md5_code: str) -> Decimal:
    """
    Tính bias trung bình từ 6 hàm băm.
    """
    biases = compute_multiple_biases(md5_code)
    bias_values = list(biases.values())
    avg_bias = sum(bias_values) / Decimal(len(bias_values))
    return avg_bias

def combine_weighted_factor(md5_code: str) -> Decimal:
    """
    Kết hợp hệ số cược từ 6 hàm băm.
    """
    factor_md5 = parse_hash_to_factor(md5_code)
    sha1_code = hashlib.sha1(md5_code.encode()).hexdigest()
    factor_sha1 = parse_hash_to_factor(sha1_code)
    sha256_code = hashlib.sha256(md5_code.encode()).hexdigest()
    factor_sha256 = parse_hash_to_factor(sha256_code)
    sha3_code = hashlib.sha3_256(md5_code.encode()).hexdigest()
    factor_sha3 = parse_hash_to_factor(sha3_code)
    blake2b_code = hashlib.blake2b(md5_code.encode()).hexdigest()
    factor_blake2b = parse_hash_to_factor(blake2b_code)
    sha512_code = hashlib.sha512(md5_code.encode()).hexdigest()
    factor_sha512 = parse_hash_to_factor(sha512_code)
    return (factor_md5 + factor_sha1 + factor_sha256 + factor_sha3 + factor_blake2b + factor_sha512) / Decimal(6)

# ---------------------------------------------------------------------------
# PHẦN 3: HÀM DỰ ĐOÁN "TÀI – XỈU" TRUNG LẬP (UNBIASED)
# ---------------------------------------------------------------------------
def determine_tai_xiu_unbiased(md5_code: str) -> (str, Decimal, Decimal, Decimal, Decimal):
    """
    Dự đoán kết quả "Tài" hay "Xỉu" một cách trung lập (không thiên vị).
    Sử dụng trung bình xác suất từ 6 hàm băm và so sánh trực tiếp với ngưỡng 0.5:
      - Nếu avg_probability >= 0.5 ⇒ "Tài", ngược lại "Xỉu".
    Đồng thời trả về:
      - threshold (0.5),
      - avg_probability,
      - confidence (khoảng cách tuyệt đối giữa avg_probability và 0.5),
      - variance của các xác suất.
    """
    avg_probability, variance = compute_weighted_probability(md5_code)
    threshold = Decimal("0.5")
    outcome = "Tài" if avg_probability >= threshold else "Xỉu"
    confidence = abs(avg_probability - threshold)
    return outcome, threshold, avg_probability, confidence, variance

# ---------------------------------------------------------------------------
# PHẦN 4: THUẬT TOÁN DỰ ĐOÁN XÚC XẮC TỔNG 3 XÚC XẮC
# ---------------------------------------------------------------------------
def predict_dice_sum(md5_code: str) -> int:
    """
    Dự đoán tổng điểm của 3 xúc xắc dựa trên mã MD5:
      - dice_sum1: sử dụng trực tiếp avg_probability ánh xạ về khoảng [3,18].
      - dice_sum2: sử dụng avg_probability cộng thêm weighted_bias (điều chỉnh tác động của bias) và ánh xạ tương tự.
      - Kết quả cuối cùng được lấy trung bình của hai dự đoán.
    """
    avg_probability, _ = compute_weighted_probability(md5_code)
    weighted_bias = compute_weighted_bias(md5_code)
    dice_sum1 = int((avg_probability * Decimal(16)).to_integral_value(rounding=ROUND_FLOOR)) + 3
    dice_sum2 = int((min(avg_probability + weighted_bias, Decimal(1)) * Decimal(16)).to_integral_value(rounding=ROUND_FLOOR)) + 3
    predicted = round((dice_sum1 + dice_sum2) / 2)
    return predicted

def analyze_hashes_updated(md5_input: str) -> dict:
    """
    Phân tích một chuỗi MD5 và trả về các thông số với dự đoán trung lập:
      - md5, avg_probability, variance, threshold (0.5),
      - base_factor, confidence, outcome và predicted_sum (tổng 3 xúc xắc dự đoán).
    """
    outcome, threshold, avg_probability, confidence, variance = determine_tai_xiu_unbiased(md5_input)
    base_factor = combine_weighted_factor(md5_input)
    predicted_sum = predict_dice_sum(md5_input)
    return {
        'md5': md5_input,
        'avg_probability': avg_probability,
        'variance': variance,
        'threshold': threshold,
        'base_factor': base_factor,
        'confidence': confidence,
        'outcome': outcome,
        'predicted_sum': predicted_sum
    }

def analyze_multiple_md5(md5_inputs: list) -> dict:
    """
    Phân tích nhiều mã MD5 (các chuỗi hợp lệ).
      - Tính trung bình avg_probability, threshold (luôn 0.5), base_factor trên tập các mẫu.
      - Dự đoán tổng hợp: "Tài" nếu avg_probability trung bình >= 0.5, ngược lại "Xỉu".
      - Tính trung bình dự đoán tổng 3 xúc xắc.
    """
    valid_hashes = [h.strip() for h in md5_inputs if validate_md5(h.strip())]
    if not valid_hashes:
        return None
    total_probability = Decimal(0)
    total_variance = Decimal(0)
    total_factor = Decimal(0)
    total_predicted_sum = 0
    analyses = []
    for md5_code in valid_hashes:
        analysis = analyze_hashes_updated(md5_code)
        analyses.append(analysis)
        total_probability += analysis['avg_probability']
        total_variance += analysis['variance']
        total_factor += analysis['base_factor']
        total_predicted_sum += analysis['predicted_sum']
    n = Decimal(len(valid_hashes))
    avg_probability = total_probability / n
    avg_variance = total_variance / n
    avg_factor = total_factor / n
    avg_predicted_sum = round(total_predicted_sum / len(valid_hashes))
    final_outcome = "Tài" if avg_probability >= Decimal("0.5") else "Xỉu"
    return {
        'md5_list': valid_hashes,
        'avg_probability': avg_probability,
        'avg_variance': avg_variance,
        'threshold': Decimal("0.5"),
        'avg_base_factor': avg_factor,
        'final_outcome': final_outcome,
        'avg_predicted_sum': avg_predicted_sum,
        'details': analyses
    }

# ---------------------------------------------------------------------------
# PHẦN 5: HÀM MÔ PHỎNG MONTE CARLO VỚI PERTURBATION CHO MẪU NGƯỜI DÙNG
# ---------------------------------------------------------------------------
def perturb_md5(md5_sample: str) -> str:
    """
    Tạo phiên bản ‘perturbation’ của chuỗi MD5 bằng cách thay đổi ngẫu nhiên 1 ký tự.
    Chiều dài vẫn là 32 ký tự, chỉ thay đổi 1 ký tự thành 1 giá trị khác (0-9, a-f).
    """
    hex_chars = "0123456789abcdef"
    md5_list = list(md5_sample)
    pos = random.randrange(len(md5_list))
    original = md5_list[pos]
    choices = [ch for ch in hex_chars if ch != original]
    md5_list[pos] = random.choice(choices)
    return "".join(md5_list)

def simulate_user_md5(md5_samples: list, iterations: int = 1000) -> dict:
    """
    Thực hiện mô phỏng Monte Carlo cho từng mẫu MD5 được nhập:
      - Với mỗi mẫu, tạo ra 'iterations' phiên bản perturbation.
      - Tính toán outcome, avg_probability, threshold (0.5), base_factor và predicted_sum cho từng phiên.
      - Tổng hợp kết quả cho mỗi mẫu: tỷ lệ "Tài", "Xỉu", trung bình các tham số và trung bình tổng dự đoán.
    """
    simulation_results = {}
    for md5_sample in md5_samples:
        if not validate_md5(md5_sample):
            continue
        outcomes = []
        prob_list = []
        factor_list = []
        predicted_sum_list = []
        for _ in range(iterations):
            perturbed = perturb_md5(md5_sample)
            analysis = analyze_hashes_updated(perturbed)
            outcomes.append(analysis['outcome'])
            prob_list.append(float(analysis['avg_probability']))
            factor_list.append(float(analysis['base_factor']))
            predicted_sum_list.append(analysis['predicted_sum'])
        tai_percentage = outcomes.count("Tài") / iterations * 100
        xiu_percentage = outcomes.count("Xỉu") / iterations * 100
        simulation_results[md5_sample] = {
            'iterations': iterations,
            'tai_percentage': tai_percentage,
            'xiu_percentage': xiu_percentage,
            'avg_probability': mean(prob_list),
            'threshold': 0.5,
            'avg_base_factor': mean(factor_list),
            'avg_predicted_sum': round(mean(predicted_sum_list))
        }
    return simulation_results

# ---------------------------------------------------------------------------
# PHẦN 6: BOT TELEGRAM – GIAO DIỆN TRỰC TIẾP
# ---------------------------------------------------------------------------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text(
        "Chào mừng đến với Bot Tài Xỉu (phiên bản version1)!\n\nNhập số vốn ban đầu của bạn (ví dụ: 15000 cho 15k):"
    )
    return CAPITAL

async def set_capital(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        capital = Decimal(update.message.text.strip())
        context.user_data['capital'] = Decimal(round(float(capital) / 1000) * 1000)
        await update.message.reply_text(
            f"Số vốn ban đầu của bạn: {context.user_data['capital']} đơn vị\nNhập mục tiêu cần đạt (ví dụ: 30000 cho 30k):"
        )
        return TARGET
    except Exception:
        await update.message.reply_text("Số vốn không hợp lệ, hãy nhập lại:")
        return CAPITAL

async def set_target(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    try:
        target = Decimal(update.message.text.strip())
        context.user_data['target'] = Decimal(round(float(target) / 1000) * 1000)
        context.user_data['round'] = 1
        await update.message.reply_text(
            f"Mục tiêu của bạn: {context.user_data['target']} đơn vị\nBắt đầu vòng cược!\nNhập các mã MD5 (nhiều mã, cách nhau dấu phẩy):"
        )
        return HASH_INPUT
    except Exception:
        await update.message.reply_text("Mục tiêu không hợp lệ, hãy nhập lại:")
        return TARGET

async def process_round(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    hash_input = update.message.text.strip().lower()
    if hash_input.startswith("exit"):
        await update.message.reply_text("Kết thúc trò chơi. Hẹn gặp lại!")
        return ConversationHandler.END
    hash_list = hash_input.split(",")
    aggregated = analyze_multiple_md5(hash_list)
    if aggregated is None:
        await update.message.reply_text("Không có mã MD5 hợp lệ nào. Hãy nhập lại:")
        return HASH_INPUT
    reply = (
        f"**KẾT QUẢ PHÂN TÍCH TỔNG HỢP (V1)**\n"
        f"Mã MD5 hợp lệ: {aggregated['md5_list']}\n"
        f"Xác suất trung bình: {aggregated['avg_probability']:.10f}\n"
        f"Độ phân tán: {aggregated['avg_variance']:.10f}\n"
        f"Ngưỡng (trung lập): {aggregated['threshold']:.2f}\n"
        f"Hệ số cược trung bình: {aggregated['avg_base_factor']:.3f}\n"
        f"Dự đoán cuối cùng: {aggregated['final_outcome']}\n"
        f"Dự đoán tổng 3 xúc xắc: {aggregated['avg_predicted_sum']}\n"
    )
    await update.message.reply_text(reply, parse_mode=ParseMode.MARKDOWN)
    capital = context.user_data['capital']
    target = context.user_data['target']
    advised_bet = int(round(min((target - capital), capital * Decimal(aggregated['avg_base_factor'])) / 1000.0) * 1000)
    context.user_data['last_bet'] = advised_bet
    reply2 = (
        f"Lời khuyên cược: đặt {advised_bet} đơn vị.\n"
        f"Số vốn còn lại sau cược: {capital - advised_bet}\n"
        "Sau cược, nhập kết quả của vòng này: 'win' hoặc 'lose'."
    )
    context.user_data['capital'] = capital - advised_bet
    await update.message.reply_text(reply2)
    return RESULT

async def process_result(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    outcome = update.message.text.strip().lower()
    bet = context.user_data.get('last_bet', 0)
    capital = context.user_data['capital']
    if outcome == "win":
        win_amount = int(round(Decimal(bet) * Decimal("1.98") / 1000.0) * 1000)
        context.user_data['capital'] = capital + win_amount
        await update.message.reply_text(
            f"Bạn thắng! Nhận được {win_amount} đơn vị.\nSố vốn hiện tại: {context.user_data['capital']}"
        )
    elif outcome == "lose":
        await update.message.reply_text(f"Bạn thua! Số vốn hiện tại: {capital}")
    else:
        await update.message.reply_text("Kết quả không hợp lệ, hãy nhập lại 'win' hoặc 'lose':")
        return RESULT
    if context.user_data['capital'] >= context.user_data['target']:
        await update.message.reply_text("Chúc mừng! Bạn đã đạt hoặc vượt mục tiêu.")
        return ConversationHandler.END
    else:
        context.user_data['round'] += 1
        await update.message.reply_text(
            f"Vòng {context.user_data['round']}: Nhập các mã MD5 cho vòng cược tiếp theo (hoặc nhập 'exit' để kết thúc):"
        )
        return HASH_INPUT

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Trò chơi đã kết thúc. Hẹn gặp lại!")
    return ConversationHandler.END

async def simulate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if context.args:
        md5_sample = context.args[0].strip().lower()
        if not validate_md5(md5_sample):
            await update.message.reply_text(
                "Mẫu MD5 không hợp lệ. Vui lòng nhập lại mẫu MD5 hợp lệ và số mẫu mô phỏng, ví dụ:\n"
                "/simulate d41d8cd98f00b204e9800998ecf8427e 1000"
            )
            return
        try:
            num_samples = int(context.args[1]) if len(context.args) > 1 else 1000
        except (IndexError, ValueError):
            num_samples = 1000
    else:
        await update.message.reply_text(
            "Vui lòng nhập mẫu MD5 và số mẫu mô phỏng, ví dụ:\n"
            "/simulate d41d8cd98f00b204e9800998ecf8427e 1000"
        )
        return
    simulation_result = simulate_user_md5([md5_sample], num_samples)
    sample, result = next(iter(simulation_result.items()))
    reply = (
        f"Kết quả mô phỏng Monte Carlo cho mẫu MD5: {sample}\n"
        f"- Số lần mô phỏng: {result['iterations']}\n"
        f"- Tỷ lệ 'Tài': {result['tai_percentage']:.2f}%\n"
        f"- Tỷ lệ 'Xỉu': {result['xiu_percentage']:.2f}%\n"
        f"- Xác suất trung bình: {result['avg_probability']:.10f}\n"
        f"- Ngưỡng (trung lập): 0.50\n"
        f"- Hệ số cược trung bình: {result['avg_base_factor']:.3f}\n"
        f"- Dự đoán tổng 3 xúc xắc trung bình: {result['avg_predicted_sum']}\n"
    )
    await update.message.reply_text(reply)

async def simulate_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_input = update.message.text.strip().lower()
    md5_samples = [s.strip() for s in user_input.split(",") if validate_md5(s.strip())]
    if not md5_samples:
        await update.message.reply_text("Không có mẫu MD5 hợp lệ nào trong input của bạn.")
        return
    try:
        iterations = int(context.args[0]) if context.args else 1000
    except (IndexError, ValueError):
        iterations = 1000
    simulation_results = simulate_user_md5(md5_samples, iterations)
    reply_lines = []
    for sample, result in simulation_results.items():
        line = (
            f"Mẫu MD5: {sample}\n"
            f"  - Số lần mô phỏng: {result['iterations']}\n"
            f"  - Tỷ lệ 'Tài': {result['tai_percentage']:.2f}%\n"
            f"  - Tỷ lệ 'Xỉu': {result['xiu_percentage']:.2f}%\n"
            f"  - Xác suất trung bình: {result['avg_probability']:.10f}\n"
            f"  - Ngưỡng (trung lập): 0.50\n"
            f"  - Hệ số cược trung bình: {result['avg_base_factor']:.3f}\n"
            f"  - Dự đoán tổng 3 xúc xắc trung bình: {result['avg_predicted_sum']}\n"
        )
        reply_lines.append(line)
    await update.message.reply_text("\n".join(reply_lines))

def main():
    # Thay "YOUR_TELEGRAM_BOT_TOKEN_HERE" bằng token thật của Bot Telegram.
    app = ApplicationBuilder().token("7789180148:AAHzAdGMxWS3IWXkk-VoVpP8zoAsGkITALQ").build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            CAPITAL: [MessageHandler(filters.TEXT & ~filters.COMMAND, set_capital)],
            TARGET: [MessageHandler(filters.TEXT & ~filters.COMMAND, set_target)],
            HASH_INPUT: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_round)],
            RESULT: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_result)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
    )

    app.add_handler(CommandHandler("simulate", simulate))
    app.add_handler(CommandHandler("simulate_input", simulate_input))
    app.add_handler(conv_handler)

    print("Bot đang chạy...")
    app.run_polling()

if __name__ == '__main__':
    main()
