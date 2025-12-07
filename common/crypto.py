"""
Криптографические функции для электронного голосования
"""
import random
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Util import number
import json


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