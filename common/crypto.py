"""
Криптографические функции для электронного голосования
"""
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util import number
import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dss import EntropyCollector, generate_prime, miller_rabin


class RSACrypto:
    """Класс для работы с RSA шифрованием"""

    @staticmethod
    def generate_keypair(bits: int = 2048) -> dict[str, any]:
        """Генерация пары RSA ключей"""
        key = RSA.generate(bits)

        return {
            'private_key': key.export_key().decode('utf-8'),
            'public_key': key.publickey().export_key().decode('utf-8'),
            'm': key.n,  # модуль
            'e': key.e,  # открытая экспонента
            'd': key.d  # закрытая экспонента
        }

    @staticmethod
    def encrypt_number(number: int, m: int, e: int) -> int:
        """Шифрование числа с использованием параметров RSA"""
        return pow(number, e, m)

    @staticmethod
    def decrypt_number(encrypted: int, m: int, d: int) -> int:
        """Дешифрование числа с использованием параметров RSA"""
        return pow(encrypted, d, m)


class FFSCrypto:
    """Класс для аутентификации по схеме Feige-Fiat-Shamir"""

    def __init__(self, entropy_collector: EntropyCollector = None):
        """Инициализация FFS"""
        self.ec = entropy_collector if entropy_collector else EntropyCollector()
        self.ec.add_os_entropy(64)
        self.ec.add_time_jitter(256)
        
        self.p = None
        self.q = None
        self.n = None
        self.s = None
        self.v = None

    def generate_server_params(self, bits: int = 512) -> dict[str, int]:
        """
        Генерация параметров сервера (p, q, n)
        
        Args:
            bits: размер простых чисел p и q в битах
            
        Returns:
            Словарь с параметрами {'n': n, 'p': p, 'q': q}
        """
        print("FFS: Начинается генерация параметров сервера...")
        
        self.ec.add_os_entropy(128)
        self.ec.add_time_jitter(512)
        
        print(f"FFS: Генерация первого простого числа p ({bits} бит)...")
        self.p = generate_prime(self.ec, bits)
        print(f"FFS: Простое число p сгенерировано: {self.p}")
        
        self.ec.add_os_entropy(128)
        self.ec.add_time_jitter(512)
        
        print(f"FFS: Генерация второго простого числа q ({bits} бит)...")
        self.q = generate_prime(self.ec, bits)
        print(f"FFS: Простое число q сгенерировано: {self.q}")
        
        self.n = self.p * self.q
        print(f"FFS: Вычислен модуль n = p * q = {self.n}")
        
        return {
            'n': self.n,
            'p': self.p,
            'q': self.q
        }

    def generate_client_keys(self, n: int) -> dict[str, int]:
        """
        Генерация ключей клиента (s - секретный, v - публичный)
        
        Args:
            n: модуль из параметров сервера
            
        Returns:
            Словарь с ключами {'s': s, 'v': v}
        """
        print("FFS: Начинается генерация ключей клиента...")
        
        self.n = n
        self.ec.add_os_entropy(64)
        self.ec.add_time_jitter(256)
        
        prng = self.ec.get_prng()
        
        print("FFS: Генерация секретного ключа s...")
        self.s = prng.randint(2, n - 1)
        print(f"FFS: Секретный ключ s сгенерирован")
        
        print("FFS: Вычисление публичного ключа v = s^2 mod n...")
        self.v = pow(self.s, 2, n)
        print(f"FFS: Публичный ключ v = {self.v}")
        
        return {
            's': self.s,
            'v': self.v
        }

    def create_commitment(self, n: int) -> dict[str, int]:
        """
        Создание обязательства (commitment) для аутентификации
        Шаг 1 протокола FFS
        
        Args:
            n: модуль из параметров сервера
            
        Returns:
            Словарь {'r': r, 'x': x} где r - случайное число, x = r^2 mod n
        """
        print("\n=== FFS АУТЕНТИФИКАЦИЯ: Шаг 1 - Создание обязательства ===")
        
        self.n = n
        self.ec.add_os_entropy(32)
        self.ec.add_time_jitter(128)
        
        prng = self.ec.get_prng()
        
        print("FFS: Клиент генерирует случайное число r...")
        r = prng.randint(2, n - 1)
        print(f"FFS: Случайное число r сгенерировано")
        
        print("FFS: Клиент вычисляет x = r^2 mod n...")
        x = pow(r, 2, n)
        print(f"FFS: Обязательство x = {x}")
        print("FFS: Обязательство отправляется серверу")
        
        return {
            'r': r,
            'x': x
        }

    def create_response(self, r: int, s: int, b: int, n: int) -> int:
        """
        Создание ответа на вызов сервера
        Шаг 3 протокола FFS
        
        Args:
            r: случайное число из commitment
            s: секретный ключ клиента
            b: вызов от сервера (0 или 1)
            n: модуль
            
        Returns:
            y = r * s^b mod n
        """
        print(f"\n=== FFS АУТЕНТИФИКАЦИЯ: Шаг 3 - Формирование ответа ===")
        print(f"FFS: Получен вызов от сервера: b = {b}")
        
        if b == 0:
            print("FFS: Вызов b = 0, вычисляем y = r mod n")
            y = r % n
        else:
            print("FFS: Вызов b = 1, вычисляем y = r * s mod n")
            y = (r * s) % n
        
        print(f"FFS: Ответ y = {y}")
        print("FFS: Ответ отправляется серверу для проверки")
        
        return y

    @staticmethod
    def create_challenge(ec: EntropyCollector = None) -> int:
        """
        Создание вызова (challenge) от сервера
        Шаг 2 протокола FFS
        
        Args:
            ec: коллектор энтропии (опционально)
            
        Returns:
            b: случайный бит (0 или 1)
        """
        print("\n=== FFS АУТЕНТИФИКАЦИЯ: Шаг 2 - Генерация вызова ===")
        
        if ec is None:
            ec = EntropyCollector()
            ec.add_os_entropy(16)
            ec.add_time_jitter(64)
        
        prng = ec.get_prng()
        b = prng.randint(0, 1)
        
        print(f"FFS: Сервер генерирует случайный вызов b = {b}")
        print("FFS: Вызов отправляется клиенту")
        
        return b

    @staticmethod
    def verify_response(x: int, y: int, v: int, b: int, n: int) -> bool:
        """
        Проверка ответа клиента
        Шаг 4 протокола FFS
        
        Args:
            x: обязательство от клиента
            y: ответ от клиента
            v: публичный ключ клиента
            b: вызов от сервера
            n: модуль
            
        Returns:
            True если проверка прошла успешно
        """
        print("\n=== FFS АУТЕНТИФИКАЦИЯ: Шаг 4 - Проверка ответа ===")
        print(f"FFS: Сервер проверяет: y^2 mod n == x * v^b mod n")
        
        left = pow(y, 2, n)
        print(f"FFS: Левая часть: y^2 mod n = {left}")
        
        right = (x * pow(v, b, n)) % n
        print(f"FFS: Правая часть: x * v^{b} mod n = {right}")
        
        result = (left == right)
        
        if result:
            print("FFS: ✓ ПРОВЕРКА УСПЕШНА! Клиент прошел аутентификацию")
        else:
            print("FFS: ✗ ПРОВЕРКА ПРОВАЛЕНА! Аутентификация не пройдена")
        
        return result


class VotingCrypto:
    """Криптография для системы голосования"""

    @staticmethod
    def create_blinded_bulletin(choice: int, m: int, e: int, q_bits: int = 64) -> dict[str, any]:
        """
        Создание затененного (ослепленного) бюллетеня

        Args:
            choice: 1 (воздержался), 2 (за), 3 (против)
            m, e: параметры RSA открытого ключа
            q_bits: битность случайного простого числа q

        Returns:
            Словарь с данными бюллетеня
        """
        if choice not in [1, 2, 3]:
            raise ValueError("Выбор должен быть 1, 2 или 3")

        # Генерация случайного простого числа q
        q = number.getPrime(q_bits)

        # Затенение: t = b * q
        t = choice * q

        # Шифрование: f = t^e mod m
        f = pow(t, e, m)

        return {
            'choice': choice,
            'q': q,
            't': t,
            'f': f,
            'm': m,
            'e': e
        }

    @staticmethod
    def calculate_voting_results(bulletins: list, m: int, d: int) -> dict[str, any]:
        """
        Подсчет результатов голосования

        Args:
            bulletins: список бюллетеней (словарей с полем 'f')
            m, d: параметры RSA закрытого ключа

        Returns:
            Словарь с результатами
        """
        if not bulletins:
            return {
                'total': 0,
                'for': 0,
                'against': 0,
                'abstained': 0,
                'F': 0,
                'Q': 0,
                'R': 0
            }

        # Шаг 1: Произведение всех зашифрованных бюллетеней
        F = 1
        for bulletin in bulletins:
            f_value = bulletin.get('f')
            if isinstance(f_value, int):
                F = (F * f_value) % m

        # Шаг 2: Дешифрование произведения
        Q = pow(F, d, m)

        # Шаг 3: Анализ делимости
        temp = Q
        votes_for = 0
        votes_against = 0

        # Считаем степень двойки (голоса "за")
        while temp % 2 == 0:
            votes_for += 1
            temp //= 2

        # Считаем степень тройки (голоса "против")
        while temp % 3 == 0:
            votes_against += 1
            temp //= 3

        # Остаток - произведение всех q
        R = temp

        total_bulletins = len(bulletins)
        total_voted = votes_for + votes_against

        return {
            'total': total_bulletins,
            'for': votes_for,
            'against': votes_against,
            'abstained': total_bulletins - total_voted,
            'F': F,
            'Q': Q,
            'R': R
        }

    @staticmethod
    def verify_bulletin(bulletin: dict[str, any], m: int, e: int) -> tuple[bool, str]:
        """Проверка целостности бюллетеня"""
        try:
            # Проверяем обязательные поля
            required_fields = ['choice', 'q', 't', 'f', 'm', 'e']
            for field in required_fields:
                if field not in bulletin:
                    return False, f"Отсутствует поле: {field}"

            # Проверяем параметры RSA
            if bulletin['m'] != m:
                return False, f"Неверный параметр m: {bulletin['m']} != {m}"

            if bulletin['e'] != e:
                return False, f"Неверный параметр e: {bulletin['e']} != {e}"

            # Проверяем допустимость выбора
            if bulletin['choice'] not in [1, 2, 3]:
                return False, f"Неверное значение choice: {bulletin['choice']}"

            # Проверяем что q >= 5
            if bulletin['q'] < 5:
                return False, f"Значение q должно быть >= 5, получено: {bulletin['q']}"

            # Проверяем вычисления
            t_calculated = bulletin['choice'] * bulletin['q']
            if t_calculated != bulletin['t']:
                return False, f"Неверное значение t: {t_calculated} != {bulletin['t']}"

            f_calculated = pow(bulletin['t'], bulletin['e'], bulletin['m'])
            if f_calculated != bulletin['f']:
                return False, f"Неверное значение f: {f_calculated} != {bulletin['f']}"

            return True, "Бюллетень корректен"

        except Exception as e:
            return False, f"Ошибка проверки: {e}"