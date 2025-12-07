import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import os
import time



class PRNG:
    def __init__(self, seed=None):
        if seed is None:
            seed = os.urandom(32) + int(time.time_ns()).to_bytes(8, 'little')
        self.state = hashlib.sha256(seed).digest()
        self.counter = 0

    def next_bytes(self, n):
        out = bytearray()
        while len(out) < n:
            block = hashlib.sha256(self.state + self.counter.to_bytes(8, 'little')).digest()
            out.extend(block)
            self.counter += 1
        # обновляем состояние (reseed-like шаг) для диффузии
        self.state = hashlib.sha256(self.state + out[:32]).digest()
        return bytes(out[:n])

    def next_int(self, bits):
        byte_len = (bits + 7) // 8
        val = int.from_bytes(self.next_bytes(byte_len), 'big')
        excess = byte_len * 8 - bits
        if excess > 0:
            val &= (1 << bits) - 1
        return val

    def randint(self, low, high):
        """
        Случайное число в диапазоне [low, high] с устранением смещения.
        """
        if high < low:
            raise ValueError("PRNG.randint: high < low")
        span = high - low + 1
        bits = span.bit_length()
        while True:
            r = self.next_int(bits)
            if r < span:
                return low + r


class EntropyCollector:
    """
    Сбор энтропии из:
    - os.urandom
    - джиттера времени
    - событий мыши
    - формула Клод Шенона
    И преобразование в случайные биты/PRNG.
    """
    def __init__(self):
        self.pool = bytearray()
        self.mouse_events = 0

    def add_os_entropy(self, n=64):
        self.pool += os.urandom(n)

    def add_time_jitter(self, rounds=1024):
        last = time.perf_counter_ns()
        for _ in range(rounds):
            now = time.perf_counter_ns()
            diff = now - last
            self.pool += diff.to_bytes(8, 'little', signed=False)
            last = now
            # минимальная системная задержка
            time.sleep(0)
        # перемешивание пула
        self.pool += hashlib.sha256(self.pool).digest()
        # ограничим размер пула
        if len(self.pool) > 8192:
            self.pool = bytearray(hashlib.sha256(self.pool).digest())

    def add_mouse_event(self, x, y):
        self.mouse_events += 1
        t = time.perf_counter_ns()
        self.pool += x.to_bytes(4, 'little', signed=False)
        self.pool += y.to_bytes(4, 'little', signed=False)
        self.pool += t.to_bytes(8, 'little', signed=False)
        if len(self.pool) > 4096:
            self.pool = bytearray(hashlib.sha256(self.pool).digest())

    def ensure_seed(self):
        if len(self.pool) < 64:
            self.add_os_entropy(64)
            self.add_time_jitter(256)

    def get_random_bits(self, bits):
        """
        DRBG на базе SHA-256 из пула энтропии для получения int указанной битности.
        """
        self.ensure_seed()
        out = bytearray()
        seed = hashlib.sha256(self.pool).digest()
        counter = 0
        while len(out) * 8 < bits:
            h = hashlib.sha256(seed + counter.to_bytes(8, 'little')).digest()
            out += h
            counter += 1
        byte_len = (bits + 7) // 8
        out = out[:byte_len]
        excess = byte_len * 8 - bits
        if excess > 0:
            out[0] &= (0xFF >> excess)
        # обновляем пул
        self.pool = bytearray(hashlib.sha256(self.pool + out).digest())
        return int.from_bytes(out, 'big')

    def get_prng(self):
        """
        Создать PRNG, инициализированный текущим пулом энтропии.
        """
        self.ensure_seed()
        seed = hashlib.sha256(bytes(self.pool)).digest()
        # Доп. диффузия
        seed = hashlib.sha256(seed + int(time.time_ns()).to_bytes(8, 'little')).digest()
        return PRNG(seed)

def miller_rabin(n, prng: PRNG, k=32):
    """
    Тест Миллера—Рабина с собственным PRNG.
    """
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19,
                    23, 29, 31, 37, 41, 43, 47]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n-1 = d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = prng.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_prime(ec: EntropyCollector, bits):
    """
    Генерация случайного простого числа заданной битности.
    """
    prng = ec.get_prng()
    while True:
        candidate = ec.get_random_bits(bits)
        candidate |= (1 << (bits - 1))  # задаём битность
        candidate |= 1                  # делаем нечётным
        if miller_rabin(candidate, prng):
            return candidate

# ==========================
# Параметры и ключи DSA
# ==========================

class DSA:
    """
    Классический DSA (DSS):
    - q: ~160 бит простое
    - p: ~1024 бит, p-1 кратно q
    - g: генератор порядка q в Z_p*
    """
    def __init__(self, ec: EntropyCollector):
        self.ec = ec
        self.prng = ec.get_prng()
        self.p = None
        self.q = None
        self.g = None
        self.x = None  # приватный ключ
        self.y = None  # публичный ключ

    def _refresh_prng(self):
        self.prng = self.ec.get_prng()

    def generate_parameters(self, q_bits=160, p_bits=1024, max_tries=5000):
        self._refresh_prng()
        self.q = generate_prime(self.ec, q_bits)

        # Ищем p = k*q + 1 с нужной длиной и простотой
        target = 1 << (p_bits - 1)
        base_k = target // self.q
        found = False

        for i in range(max_tries):
            delta = self.prng.next_int(32)
            k = base_k + delta + i
            p_candidate = k * self.q + 1
            if p_candidate.bit_length() != p_bits:
                continue
            if miller_rabin(p_candidate, self.prng):
                self.p = p_candidate
                found = True
                break

        if not found:
            raise ValueError("Не удалось сгенерировать p нужной длины за допустимое число попыток")

        while True:
            # 1 < h < p-1
            h = 2 + (self.prng.next_int(self.p.bit_length() - 2) % (self.p - 3))
            g_candidate = pow(h, (self.p - 1) // self.q, self.p)
            if g_candidate > 1:
                self.g = g_candidate
                break

    def generate_keys(self):
        if not all([self.p, self.q, self.g]):
            raise ValueError("Параметры DSA не сгенерированы")
        # приватный x в [1, q-1]
        self._refresh_prng()
        self.x = 1 + (self.prng.next_int(self.q.bit_length()) % (self.q - 1))
        # публичный y = a^x mod p
        self.y = pow(self.g, self.x, self.p)

    @staticmethod
    def hash_message(msg: str) -> bytes:
        # Классический DSA использует SHA-1
        return hashlib.sha1(msg.encode('utf-8')).digest()

    def sign(self, msg: str):
        """
        Подпись DSA: (r, s, H). H — хэш для детектирования подмены сообщения.
        """
        if self.x is None:
            raise ValueError("Ключи не сгенерированы")
        H = int.from_bytes(self.hash_message(msg), 'big')
        self._refresh_prng()
        while True:
            # Эфемерный k в [1, q-1]
            k = 1 + (self.prng.next_int(self.q.bit_length()) % (self.q - 1))
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue
            try:
                k_inv = pow(k, -1, self.q)
            except ValueError:
                # k и q не взаимно просты — перегенерируем k
                continue
            s = (k_inv * (H + self.x * r)) % self.q
            if s != 0:
                return (r, s, H)

    def verify(self, msg: str, signature):
        """
        Проверка подписи DSA.
        """
        if self.y is None:
            raise ValueError("Публичный ключ не определён")
        (r, s, H_sig) = signature
        if not (0 < r < self.q and 0 < s < self.q):
            return False, "Неверные параметры подписи: r или s вне диапазона (0, q)"

        H_msg = int.from_bytes(self.hash_message(msg), 'big')
        if H_msg != H_sig:
            return False, "Несоответствие хэш-значения: сообщение изменено относительно подписанного"

        try:
            w = pow(s, -1, self.q)
        except ValueError:
            return False, "Невозможно вычислить обратное к s по модулю q (s не взаимно просто с q)"

        u1 = (H_msg * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self.y, u2, self.p)) % self.p) % self.q
        if v == r:
            return True, "Подпись корректна"
        else:
            return False, "Подпись некорректна: несоответствие контрольного значения v"

# ==========================
# GUI: Отправитель и Получатель
# ==========================

class DSSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DSS (DSA) — Отправитель и Получатель")

        # Общие структуры
        self.entropy = EntropyCollector()
        self.dsa = DSA(self.entropy)

        # Поля для «отправки»
        self.sent_message = ""
        self.sent_signature = None

        # Основной контейнер
        main = ttk.Notebook(root)
        self.sender_frame = ttk.Frame(main, padding=10)
        self.receiver_frame = ttk.Frame(main, padding=10)
        main.add(self.sender_frame, text="Отправитель")
        main.add(self.receiver_frame, text="Получатель")
        main.pack(fill="both", expand=True)

        # Сбор энтропии: мышь
        root.bind("<Motion>", self._on_mouse)

        self._build_sender_ui()
        self._build_receiver_ui()

    def _on_mouse(self, event):
        self.entropy.add_mouse_event(event.x, event.y)

    # ---------- Отправитель ----------
    def _build_sender_ui(self):
        # Параметры и ключи
        params_box = ttk.LabelFrame(self.sender_frame, text="Параметры и ключи DSA")
        params_box.pack(fill="x", pady=5)

        btn_params = ttk.Button(params_box, text="Сгенерировать параметры (p, q, a)", command=self._gen_params)
        btn_params.pack(fill="x", pady=3)

        btn_keys = ttk.Button(params_box, text="Сгенерировать ключи (x, y)", command=self._gen_keys)
        btn_keys.pack(fill="x", pady=3)

        self.p_var = tk.StringVar()
        self.q_var = tk.StringVar()
        self.g_var = tk.StringVar()
        self.x_var = tk.StringVar()
        self.y_var = tk.StringVar()

        for label, var in [("p:", self.p_var), ("q:", self.q_var), ("a:", self.g_var),
                           ("x (приватный):", self.x_var), ("y (публичный):", self.y_var)]:
            row = ttk.Frame(params_box)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=label, width=18).pack(side="left")
            ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True)

        # Сообщение
        msg_box = ttk.LabelFrame(self.sender_frame, text="Сообщение")
        msg_box.pack(fill="both", pady=5, expand=True)
        self.sender_text = tk.Text(msg_box, height=6)
        self.sender_text.pack(fill="both", pady=3, expand=True)

        act_box = ttk.Frame(msg_box)
        act_box.pack(fill="x", pady=3)
        ttk.Button(act_box, text="Зашифровать (подготовка: хэш)", command=self._hash_sender).pack(side="left", padx=3)
        ttk.Button(act_box, text="Подписать", command=self._sign_sender).pack(side="left", padx=3)
        ttk.Button(act_box, text="Отправить", command=self._send_to_receiver).pack(side="left", padx=3)

        self.hash_var = tk.StringVar()
        self.sig_r_var = tk.StringVar()
        self.sig_s_var = tk.StringVar()
        ttk.Label(msg_box, text="Хэш (SHA-1):").pack(anchor="w")
        ttk.Entry(msg_box, textvariable=self.hash_var).pack(fill="x")
        ttk.Label(msg_box, text="Подпись r:").pack(anchor="w")
        ttk.Entry(msg_box, textvariable=self.sig_r_var).pack(fill="x")
        ttk.Label(msg_box, text="Подпись s:").pack(anchor="w")
        ttk.Entry(msg_box, textvariable=self.sig_s_var).pack(fill="x")

        # Демонстрация атак 4.1 — отправитель меняет сообщение после подписи
        attack_box = ttk.LabelFrame(self.sender_frame, text="Атака 4.1: Подмена сообщения отправителем")
        attack_box.pack(fill="x", pady=5)
        ttk.Label(attack_box, text="Суть: отправитель подписывает одно сообщение, затем меняет его и пытается отправить со старой подписью.").pack(fill="x")
        ttk.Button(attack_box, text="Изменить сообщение после подписи и отправить", command=self._attack_sender_change_message).pack(fill="x", pady=3)

    def _gen_params(self):
        try:
            self.entropy.add_os_entropy(64)
            self.entropy.add_time_jitter(512)
            self.dsa.generate_parameters(q_bits=160, p_bits=1024)
            self.p_var.set(str(self.dsa.p))
            self.q_var.set(str(self.dsa.q))
            self.g_var.set(str(self.dsa.g))
            messagebox.showinfo("OK", "Параметры (p, q, a) успешно сгенерированы")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать параметры: {e}")

    def _gen_keys(self):
        try:
            self.entropy.add_os_entropy(64)
            self.entropy.add_time_jitter(128)
            self.dsa.generate_keys()
            self.x_var.set(str(self.dsa.x))
            self.y_var.set(str(self.dsa.y))
            messagebox.showinfo("OK", "Ключи (x, y) успешно сгенерированы")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключи: {e}")

    def _hash_sender(self):
        msg = self.sender_text.get("1.0", "end").strip()
        h = self.dsa.hash_message(msg)
        self.hash_var.set(h.hex())
        messagebox.showinfo("OK", "Хэш (SHA-1) подготовлен")

    def _sign_sender(self):
        msg = self.sender_text.get("1.0", "end").strip()
        try:
            r, s, H = self.dsa.sign(msg)
            self.sig_r_var.set(str(r))
            self.sig_s_var.set(str(s))
            self.hash_var.set(int(H).to_bytes(20, 'big').hex())
            messagebox.showinfo("OK", "Сообщение подписано (DSA)")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось подписать: {e}")

    def _send_to_receiver(self):
        # Передаём в окно получателя
        msg = self.sender_text.get("1.0", "end").strip()
        self.sent_message = msg
        try:
            r = int(self.sig_r_var.get())
            s = int(self.sig_s_var.get())
            H_bytes = bytes.fromhex(self.hash_var.get()) if self.hash_var.get() else self.dsa.hash_message(msg)
            H = int.from_bytes(H_bytes, 'big')
            self.sent_signature = (r, s, H)
        except Exception:
            self.sent_signature = None

        self.receiver_text.delete("1.0", "end")
        self.receiver_text.insert("1.0", msg)
        self.recv_r_var.set(self.sig_r_var.get())
        self.recv_s_var.set(self.sig_s_var.get())
        self.recv_hash_var.set(self.hash_var.get())
        self.recv_y_var.set(self.y_var.get())
        messagebox.showinfo("Отправлено", "Сообщение, подпись и публичный ключ отправлены получателю")

    def _attack_sender_change_message(self):
        # Меняем сообщение после подписи, но оставляем старую подпись
        original = self.sender_text.get("1.0", "end").strip()
        if not self.sig_r_var.get() or not self.sig_s_var.get():
            messagebox.showerror("Ошибка", "Сначала подпишите исходное сообщение")
            return
        tampered = original + " [ИЗМЕНЕНО ОТПРАВИТЕЛЕМ]"
        self.sender_text.delete("1.0", "end")
        self.sender_text.insert("1.0", tampered)
        # «Отправим» без переподписи
        self._send_to_receiver()
        messagebox.showwarning("Атака 4.1", "Отправитель изменил сообщение, оставив старую подпись. Получатель должен обнаружить несоответствие хэша.")

    # ---------- Получатель ----------
    def _build_receiver_ui(self):
        # Получение сообщения и подписи
        inbox_box = ttk.LabelFrame(self.receiver_frame, text="Полученное сообщение и подпись")
        inbox_box.pack(fill="both", pady=5, expand=True)

        self.receiver_text = tk.Text(inbox_box, height=6)
        self.receiver_text.pack(fill="both", pady=3, expand=True)

        self.recv_hash_var = tk.StringVar()
        self.recv_r_var = tk.StringVar()
        self.recv_s_var = tk.StringVar()
        self.recv_y_var = tk.StringVar()

        for label, var in [("Хэш (SHA-1):", self.recv_hash_var),
                           ("Подпись r:", self.recv_r_var),
                           ("Подпись s:", self.recv_s_var),
                           ("Публичный ключ y:", self.recv_y_var)]:
            ttk.Label(inbox_box, text=label).pack(anchor="w")
            ttk.Entry(inbox_box, textvariable=var).pack(fill="x")

        # Проверка подписи
        verify_box = ttk.Frame(inbox_box)
        verify_box.pack(fill="x", pady=3)
        ttk.Button(verify_box, text="Проверить подпись", command=self._verify_received).pack(side="left", padx=3)

        # Демонстрации атак 4.2 и 4.3
        attack_recv_box = ttk.LabelFrame(self.receiver_frame, text="Атаки на стороне получателя")
        attack_recv_box.pack(fill="x", pady=5)

        ttk.Label(attack_recv_box, text="4.2: Подмена сообщения получателем (с сохранением корректной подписи).").pack(anchor="w")
        ttk.Button(attack_recv_box, text="Изменить текст сообщения и проверить подпись", command=self._attack_receiver_change_message).pack(fill="x", pady=3)

        ttk.Label(attack_recv_box, text="4.3: Подмена подписи получателем (изменение r/s).").pack(anchor="w")
        ttk.Button(attack_recv_box, text="Изменить подпись и проверить", command=self._attack_receiver_change_signature).pack(fill="x", pady=3)

    def _verify_received(self):
        msg = self.receiver_text.get("1.0", "end").strip()
        try:
            r = int(self.recv_r_var.get())
            s = int(self.recv_s_var.get())
            H_bytes = bytes.fromhex(self.recv_hash_var.get())
            H = int.from_bytes(H_bytes, 'big')
            signature = (r, s, H)
        except Exception:
            messagebox.showerror("Ошибка", "Некорректный формат подписи или хэша")
            return

        # Восстановить публичный ключ y из поля
        try:
            y = int(self.recv_y_var.get())
        except Exception:
            messagebox.showerror("Ошибка", "Некорректный публичный ключ y")
            return

        # Используем текущие p, q, g, а y — как получен
        self.dsa.y = y

        ok, info = self.dsa.verify(msg, signature)
        if ok:
            messagebox.showinfo("Проверка", info)
        else:
            messagebox.showerror("Проверка", info)

    def _attack_receiver_change_message(self):
        # Получатель изменяет сообщение, оставляя подпись нетронутой
        msg = self.receiver_text.get("1.0", "end").strip()
        tampered = msg + " [ИЗМЕНЕНО ПОЛУЧАТЕЛЕМ]"
        self.receiver_text.delete("1.0", "end")
        self.receiver_text.insert("1.0", tampered)
        messagebox.showwarning("Атака 4.2", "Получатель изменил текст, сохранив подпись. Проверка должна выявить несоответствие хэша.")

    def _attack_receiver_change_signature(self):
        # Получатель меняет r или s
        try:
            r = int(self.recv_r_var.get())
            s = int(self.recv_s_var.get())
        except Exception:
            messagebox.showerror("Ошибка", "Некорректные r/s для изменения")
            return
        if self.dsa.q is None:
            messagebox.showerror("Ошибка", "Параметр q отсутствует для демонстрации изменения подписи")
            return
        s_tampered = (s + 1) % self.dsa.q
        self.recv_s_var.set(str(s_tampered))
        messagebox.showwarning("Атака 4.3", "Получатель изменил подпись (s). Проверка должна сообщить об ошибке подписи.")

# ==========================
# Запуск приложения
# ==========================

def main():
    root = tk.Tk()
    app = DSSApp(root)
    root.geometry("900x700")
    root.mainloop()

if __name__ == "__main__":
    main()





# найти атаку на dss 
# вторую проверку простоты
# разобраться с начальным массивом его можео выбирать по закону распределения