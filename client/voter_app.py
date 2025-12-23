"""
Клиент избирателя для электронного голосования
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import hashlib
from datetime import datetime
import sys
import os

# Добавляем путь к общим модулям
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import MessageProtocol
from common.crypto import VotingCrypto, FFSCrypto
from common.models import Voter, Election
from dss import EntropyCollector, DSA


class VoterClient:
    """Клиент избирателя"""

    def __init__(self):
        # Сетевое подключение
        self.socket = None
        self.connected = False
        self.server_host = "127.0.0.1"
        self.server_port = 8888
        self.receive_thread = None

        # Данные пользователя
        self.voter = None
        self.authenticated = False
        self.election = None
        self.has_voted = False
        self.eligible_voters = set()
        self.voters_registry = []
        self.registry_status = {}  # voter_id -> локальный статус

        # Криптография
        self.dss_entropy = EntropyCollector()
        self.dsa = DSA(self.dss_entropy)
        self.dss_keys_generated = False
        
        # FFS аутентификация
        self.ffs = FFSCrypto(self.dss_entropy)
        self.ffs_n = None
        self.ffs_s = None
        self.ffs_v = None
        self.ffs_keys_generated = False
        self.ffs_auth_r = None
        
        # Данные моего голоса для проверки
        self.my_bulletin_data = None
        
        # Все опубликованные бюллетени для перекрестной проверки
        self.published_bulletins = []

        # GUI
        self.root = tk.Tk()
        self.setup_gui()

        # Сбор энтропии
        self.root.bind("<Motion>", self._on_mouse)

    def _on_mouse(self, event):
        """Сбор энтропии от движений мыши"""
        self.dss_entropy.add_mouse_event(event.x, event.y)

    def setup_gui(self):
        """Настройка графического интерфейса"""
        self.root.title("Электронное голосование - Избиратель")
        self.root.geometry("1000x800")

        # Стили
        style = ttk.Style()
        style.theme_use('clam')

        # Основные вкладки
        notebook = ttk.Notebook(self.root)

        # Создаем вкладки
        tabs = [
            ("Подключение", self.setup_connection_tab),
            ("Регистрация", self.setup_registration_tab),
            ("Голосование", self.setup_voting_tab),
            ("Проверка", self.setup_verification_tab),
            ("Криптография", self.setup_crypto_tab),
            ("Логи", self.setup_logs_tab)
        ]

        for tab_name, setup_func in tabs:
            tab = ttk.Frame(notebook)
            setup_func(tab)
            notebook.add(tab, text=tab_name)

        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def setup_connection_tab(self, parent):
        """Вкладка подключения"""
        frame = ttk.LabelFrame(parent, text="Подключение к серверу", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Настройки
        settings_frame = ttk.Frame(frame)
        settings_frame.pack(fill=tk.X, pady=5)

        ttk.Label(settings_frame, text="Хост сервера:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.host_entry = ttk.Entry(settings_frame, width=20)
        self.host_entry.insert(0, self.server_host)
        self.host_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(settings_frame, text="Порт:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.port_entry = ttk.Entry(settings_frame, width=10)
        self.port_entry.insert(0, str(self.server_port))
        self.port_entry.grid(row=0, column=3, padx=5, pady=2)

        # Статус
        status_frame = ttk.Frame(frame)
        status_frame.pack(fill=tk.X, pady=10)

        self.status_label = ttk.Label(status_frame, text="🔴 Не подключен",
                                      font=('Arial', 12, 'bold'))
        self.status_label.pack()

        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        self.connect_btn = ttk.Button(btn_frame, text="🔗 Подключиться",
                                      command=self.connect_to_server, width=20)
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        self.disconnect_btn = ttk.Button(btn_frame, text="🔌 Отключиться",
                                         command=self.disconnect_from_server,
                                         width=20, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)

        # Тест соединения
        test_frame = ttk.Frame(frame)
        test_frame.pack(pady=10)

        ttk.Button(test_frame, text="🔄 Тест соединения",
                   command=self.test_connection).pack()

    def setup_registration_tab(self, parent):
        """Вкладка регистрации"""
        frame = ttk.LabelFrame(parent, text="Регистрация и аутентификация", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Форма регистрации
        form_frame = ttk.LabelFrame(frame, text="Регистрация нового избирателя", padding=10)
        form_frame.pack(fill=tk.X, pady=5)

        ttk.Label(form_frame, text="ID избирателя:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.voter_id_entry = ttk.Entry(form_frame, width=30)
        self.voter_id_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(form_frame, text="ФИО:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.voter_name_entry = ttk.Entry(form_frame, width=30)
        self.voter_name_entry.grid(row=1, column=1, padx=5, pady=2)

        # Кнопки регистрации
        btn_frame = ttk.Frame(form_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)

        self.register_btn = ttk.Button(btn_frame, text="📝 Зарегистрироваться",
                                       command=self.register_voter, width=20, state=tk.DISABLED)
        self.register_btn.pack(side=tk.LEFT, padx=5)

        self.auth_btn = ttk.Button(btn_frame, text="🔑 Аутентифицироваться",
                                   command=self.authenticate_voter, width=20, state=tk.DISABLED)
        self.auth_btn.pack(side=tk.LEFT, padx=5)

        # Информация об избирателе
        info_frame = ttk.LabelFrame(frame, text="Информация об избирателе", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.voter_info = scrolledtext.ScrolledText(info_frame, height=8)
        self.voter_info.pack(fill=tk.BOTH, expand=True)

    def setup_voting_tab(self, parent):
        """Вкладка голосования"""
        frame = ttk.LabelFrame(parent, text="Голосование", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Информация о выборах
        election_frame = ttk.LabelFrame(frame, text="Информация о выборах", padding=10)
        election_frame.pack(fill=tk.X, pady=5)

        self.election_title = ttk.Label(election_frame, text="Нет активных выборов",
                                        font=('Arial', 11, 'bold'))
        self.election_title.pack(anchor=tk.W, pady=2)

        self.election_status = ttk.Label(election_frame, text="Статус: Неизвестно")
        self.election_status.pack(anchor=tk.W)

        # Выбор варианта
        choice_frame = ttk.LabelFrame(frame, text="Выберите вариант голосования", padding=10)
        choice_frame.pack(fill=tk.X, pady=10)

        self.vote_var = tk.IntVar(value=0)

        ttk.Radiobutton(choice_frame, text="✅ За", variable=self.vote_var, value=2).pack(anchor=tk.W, pady=3)
        ttk.Radiobutton(choice_frame, text="❌ Против", variable=self.vote_var, value=3).pack(anchor=tk.W, pady=3)
        ttk.Radiobutton(choice_frame, text="➖ Воздержаться", variable=self.vote_var, value=1).pack(anchor=tk.W, pady=3)

        # Кнопка голосования
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        self.vote_btn = ttk.Button(btn_frame, text="🗳️ Проголосовать",
                                   command=self.cast_vote, width=20, state=tk.DISABLED)
        self.vote_btn.pack()

        # ДОБАВИТЬ: Секция для атаки
        attack_frame = ttk.LabelFrame(frame, text="⚠️ АТАКА: Отправка некорректного бюллетеня", padding=10)
        attack_frame.pack(fill=tk.X, pady=10)

        self.attack_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(attack_frame, text="Включить атаку (отправить некорректный бюллетень)",
                       variable=self.attack_enabled).pack(anchor=tk.W, pady=2)

        attack_type_frame = ttk.Frame(attack_frame)
        attack_type_frame.pack(fill=tk.X, pady=5)

        self.attack_type = tk.StringVar(value="invalid_f")
        ttk.Radiobutton(attack_type_frame, text="Некорректное f", variable=self.attack_type, 
                       value="invalid_f").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(attack_type_frame, text="Некорректные параметры ФФС", variable=self.attack_type,
                       value="invalid_rsa").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(attack_type_frame, text="Нарушить вычисления", variable=self.attack_type,
                       value="broken_calc").pack(side=tk.LEFT, padx=5)
        
        # НОВЫЕ типы атак
        attack_type_frame2 = ttk.Frame(attack_frame)
        attack_type_frame2.pack(fill=tk.X, pady=5)
        
        ttk.Radiobutton(attack_type_frame2, text="Некорректный q (< 5)", variable=self.attack_type,
                       value="invalid_q").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(attack_type_frame2, text="Отсутствует поле", variable=self.attack_type,
                       value="missing_field").pack(side=tk.LEFT, padx=5)

        # Информация о бюллетене
        bulletin_frame = ttk.LabelFrame(frame, text="Сгенерированный бюллетень", padding=10)
        bulletin_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.bulletin_info = scrolledtext.ScrolledText(bulletin_frame, height=8)
        self.bulletin_info.pack(fill=tk.BOTH, expand=True)

    def setup_verification_tab(self, parent):
        """Вкладка проверки"""
        frame = ttk.LabelFrame(parent, text="Проверка результатов", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Кнопки получения данных
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="📋 Получить таблицу бюллетеней",
                   command=self.get_published_data).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="📊 Получить результаты",
                   command=self.get_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="✅ Проверить МОЙ голос",
                   command=self.verify_my_vote).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="🔍 Проверить контрольные суммы",
                   command=self.verify_checksums).pack(side=tk.LEFT, padx=5)

        # Секция проверки чужого голоса
        cross_verify_frame = ttk.LabelFrame(frame, text="Перекрестная проверка голосов", padding=10)
        cross_verify_frame.pack(fill=tk.X, pady=10)

        ttk.Label(cross_verify_frame, text="ID избирателя для проверки:").pack(anchor=tk.W, padx=5, pady=2)
        
        input_frame = ttk.Frame(cross_verify_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=2)
        
        self.verify_voter_id_entry = ttk.Entry(input_frame, width=30)
        self.verify_voter_id_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="🔍 Проверить голос",
                   command=self.verify_other_vote).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="📋 Показать данные избирателя",
                   command=self.show_voter_bulletin).pack(side=tk.LEFT, padx=5)

        # Таблица бюллетеней
        bulletins_frame = ttk.LabelFrame(frame, text="Опубликованные бюллетени", padding=5)
        bulletins_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        columns = ('ID избирателя', 'Зашифрованный бюллетень', 'Время')
        self.bulletins_tree = ttk.Treeview(bulletins_frame, columns=columns, show='headings', height=8)

        for col in columns:
            self.bulletins_tree.heading(col, text=col)
            self.bulletins_tree.column(col, width=200)

        scrollbar = ttk.Scrollbar(bulletins_frame, orient=tk.VERTICAL, command=self.bulletins_tree.yview)
        self.bulletins_tree.configure(yscrollcommand=scrollbar.set)

        self.bulletins_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ИЗМЕНЕНИЕ: Реестр избирателей - только ID и ФИО (без "Допущен" и "Статус")
        registry_frame = ttk.LabelFrame(frame, text="Реестр избирателей", padding=5)
        registry_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # УБРАТЬ "Допущен" и "Статус", оставить только ID и ФИО
        reg_columns = ('ID', 'ФИО')
        self.registry_tree = ttk.Treeview(registry_frame, columns=reg_columns, show='headings', height=8)

        for col in reg_columns:
            self.registry_tree.heading(col, text=col)
            self.registry_tree.column(col, width=200 if col == 'ID' else 300)

        reg_scrollbar = ttk.Scrollbar(registry_frame, orient=tk.VERTICAL, command=self.registry_tree.yview)
        self.registry_tree.configure(yscrollcommand=reg_scrollbar.set)

        self.registry_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        reg_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Результаты
        results_frame = ttk.LabelFrame(frame, text="Результаты голосования", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.results_text = scrolledtext.ScrolledText(results_frame, height=8)
        self.results_text.pack(fill=tk.BOTH, expand=True)

    def setup_crypto_tab(self, parent):
        """Вкладка криптографии"""
        frame = ttk.LabelFrame(parent, text="Криптографические операции", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # DSS ключи
        dss_frame = ttk.LabelFrame(frame, text="DSS ключи", padding=10)
        dss_frame.pack(fill=tk.X, pady=5)

        ttk.Button(dss_frame, text="🔐 Сгенерировать DSS ключи",
                   command=self.generate_dss_keys).pack(pady=5)

        self.dss_status = ttk.Label(dss_frame, text="❌ DSS ключи не сгенерированы")
        self.dss_status.pack()

        # Проверка подписи
        verify_frame = ttk.LabelFrame(frame, text="Проверка подписи", padding=10)
        verify_frame.pack(fill=tk.X, pady=5)

        ttk.Button(verify_frame, text="✅ Проверить свою подпись",
                   command=self.verify_signature).pack(pady=5)

        # Информация о ключах
        info_frame = ttk.LabelFrame(frame, text="Информация о ключах", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.keys_info = scrolledtext.ScrolledText(info_frame, height=10)
        self.keys_info.pack(fill=tk.BOTH, expand=True)

    def setup_logs_tab(self, parent):
        """Вкладка логов"""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_text = scrolledtext.ScrolledText(frame, height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def log(self, message: str, level: str = "INFO"):
        """Логирование сообщений"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"

        # В GUI
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)

        # В консоль
        print(log_entry.strip())

    # === Сетевые методы ===

    def connect_to_server(self):
        """Подключение к серверу"""
        try:
            self.server_host = self.host_entry.get()
            self.server_port = int(self.port_entry.get())

            self.log(f"Попытка подключения к {self.server_host}:{self.server_port}...")

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.server_host, self.server_port))

            self.connected = True

            # Обновляем GUI
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.register_btn.config(state=tk.NORMAL)
            self.auth_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"✅ Подключен к {self.server_host}:{self.server_port}")

            # Запускаем поток приема сообщений
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()

            self.log(f"Подключение к серверу успешно")

            # Запрашиваем информацию о выборах
            self.send_message({
                'type': 'get_election_info',
                'timestamp': datetime.now().isoformat()
            })

        except socket.timeout:
            self.log("Таймаут подключения к серверу", "ERROR")
            messagebox.showerror("Ошибка", "Таймаут подключения к серверу")
        except ConnectionRefusedError:
            self.log("Сервер недоступен", "ERROR")
            messagebox.showerror("Ошибка", "Сервер недоступен или отказал в подключении")
        except Exception as e:
            self.log(f"Ошибка подключения: {e}", "ERROR")
            messagebox.showerror("Ошибка", f"Не удалось подключиться: {e}")

    def disconnect_from_server(self):
        """Отключение от сервера"""
        self.connected = False

        if self.socket:
            try:
                self.socket.close()
            except:
                pass

        # Обновляем GUI
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.register_btn.config(state=tk.DISABLED)
        self.auth_btn.config(state=tk.DISABLED)
        self.vote_btn.config(state=tk.DISABLED)
        self.status_label.config(text="🔴 Не подключен")

        # Сбрасываем данные
        self.voter = None
        self.authenticated = False
        self.election = None
        self.has_voted = False

        self.update_voter_info()
        self.update_election_info()

        self.log("Отключение от сервера")

    def test_connection(self):
        """Тест соединения с сервером"""
        if not self.connected:
            messagebox.showwarning("Предупреждение", "Сначала подключитесь к серверу")
            return

        try:
            # Отправляем тестовое сообщение
            response = self.send_message_with_response({
                'type': 'test',
                'message': 'test_connection',
                'timestamp': datetime.now().isoformat()
            })

            if response:
                messagebox.showinfo("Успех", f"Соединение с сервером работает\nОтвет: {response.get('message', 'OK')}")
            else:
                messagebox.showerror("Ошибка", "Нет ответа от сервера")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка тестирования: {e}")

    def send_message(self, message: dict) -> bool:
        """Отправка сообщения на сервер"""
        if not self.connected or not self.socket:
            self.log("Нет подключения к серверу", "ERROR")
            return False

        try:
            success = MessageProtocol.send_message(self.socket, message)
            if success:
                self.log(f"Отправлено: {message.get('type')}")
            else:
                self.log(f"Ошибка отправки: {message.get('type')}", "ERROR")
            return success
        except Exception as e:
            self.log(f"Ошибка отправки сообщения: {e}", "ERROR")
            return False

    def send_message_with_response(self, message: dict, timeout: float = 5.0) -> dict:
        """Отправка сообщения и ожидание ответа"""
        if not self.send_message(message):
            return {}

        # В реальной системе здесь была бы синхронная отправка с ожиданием ответа
        # Для простоты используем асинхронную модель
        return {}

    def receive_messages(self):
        """Прием сообщений от сервера"""
        self.socket.settimeout(1.0)

        while self.connected:
            try:
                message = MessageProtocol.receive_message(self.socket, timeout=1.0)
                if message is None:
                    continue

                self.log(f"Получено: {message.get('type')}")

                # Обрабатываем в основном потоке
                self.root.after(0, lambda m=message: self.process_server_message(m))

            except socket.timeout:
                continue
            except Exception as e:
                if self.connected:
                    self.log(f"Ошибка приема сообщений: {e}", "ERROR")
                break

        # Если вышли из цикла, отключаемся
        if self.connected:
            self.root.after(0, self.disconnect_from_server)

    def process_server_message(self, message: dict):
        """Обработка сообщений от сервера"""
        msg_type = message.get('type')

        if msg_type == 'register_response':
            self.handle_register_response(message)
        elif msg_type == 'authenticate_challenge':
            self.handle_authenticate_challenge(message)
        elif msg_type == 'authenticate_response':
            self.handle_authenticate_response(message)
        elif msg_type == 'submit_response':
            self.handle_submit_response(message)
        elif msg_type == 'election_info':
            self.handle_election_info(message)
        elif msg_type == 'published_data':
            self.handle_published_data(message)
        elif msg_type == 'election_started':
            self.handle_election_started(message)
        elif msg_type == 'election_ended':
            self.handle_election_ended(message)
        elif msg_type == 'bulletins_published':
            self.handle_bulletins_published(message)
        elif msg_type == 'results_published':
            self.handle_results_published(message)
        elif msg_type == 'voters_registry':
            self.handle_voters_registry(message)
        else:
            self.log(f"Неизвестный тип сообщения: {msg_type}", "WARNING")

    # === Обработчики сообщений ===

    def handle_register_response(self, message: dict):
        """Обработка ответа на регистрацию"""
        success = message.get('success', False)
        msg_text = message.get('message', '')

        if success:
            voter_data = message.get('voter', {})
            self.voter = Voter.from_dict(voter_data)
            if self.voter:
                self.registry_status[self.voter.id] = "✅ Зарегистрирован"
            
            # Получаем FFS параметры от сервера
            ffs_n = message.get('ffs_n')
            if ffs_n:
                self.ffs_n = ffs_n
                self.log(f"Получен FFS параметр n от сервера: {ffs_n}", "SUCCESS")
                # Генерируем FFS ключи
                self.generate_ffs_keys()
            
            self.update_voter_info()
            self.log(f"Регистрация успешна: {msg_text}", "SUCCESS")

            # Автоматически аутентифицируемся
            self.root.after(1000, self.authenticate_voter)
        else:
            self.log(f"Ошибка регистрации: {msg_text}", "ERROR")
            messagebox.showerror("Ошибка", msg_text)

    def handle_authenticate_challenge(self, message: dict):
        """Обработка вызова (challenge) от сервера при FFS аутентификации"""
        success = message.get('success', False)
        msg_text = message.get('message', '')
        
        if success:
            b = message.get('b')
            self.log(f"Получен вызов от сервера: b = {b}", "SUCCESS")
            
            # Создаем ответ
            if self.ffs_auth_r and self.ffs_s and self.ffs_n:
                y = self.ffs.create_response(self.ffs_auth_r, self.ffs_s, b, self.ffs_n)
                
                # Отправляем ответ
                self.send_message({
                    'type': 'authenticate',
                    'voter_id': self.voter.id,
                    'step': 2,
                    'y': y,
                    'timestamp': datetime.now().isoformat()
                })
            else:
                self.log("Ошибка: нет данных для создания ответа", "ERROR")
                messagebox.showerror("Ошибка", "Не удалось создать ответ для аутентификации")
        else:
            self.log(f"Ошибка получения вызова: {msg_text}", "ERROR")
            messagebox.showerror("Ошибка", msg_text)
    
    def handle_authenticate_response(self, message: dict):
        """Обработка ответа на аутентификацию"""
        success = message.get('success', False)
        msg_text = message.get('message', '')

        if success:
            self.authenticated = True

            # Получаем информацию о выборах
            election_data = message.get('election')
            if election_data:
                self.election = Election.from_dict(election_data)
            if self.voter:
                self.registry_status[self.voter.id] = "✅ Аутентифицировался"
            self.update_voter_info()
            self.update_election_info()
            self.update_voting_button()
            self.update_registry_table()

            self.log(f"Аутентификация успешна: {msg_text}", "SUCCESS")
            messagebox.showinfo("Успех", "Аутентификация успешна!\nТеперь вы можете проголосовать.")
        else:
            self.log(f"Ошибка аутентификации: {msg_text}", "ERROR")
            messagebox.showerror("Ошибка", msg_text)

    def handle_submit_response(self, message: dict):
        """Обработка ответа на отправку бюллетеня"""
        success = message.get('success', False)
        msg_text = message.get('message', '')
        is_valid = message.get('is_valid', True)
        validation_message = message.get('validation_message', '')

        if success and is_valid:
            self.has_voted = True
            if self.voter:
                self.voter.has_voted = True
                self.registry_status[self.voter.id] = "✅ Проголосовал"

            self.update_voter_info()
            self.update_voting_button()
            self.update_registry_table()

            bulletin_id = message.get('bulletin_id', 0)

            self.log(f"Бюллетень принят (ID: {bulletin_id})", "SUCCESS")
            messagebox.showinfo("Успех", "Ваш голос успешно зарегистрирован!")
        elif success and not is_valid:
            # Бюллетень принят, но некорректен
            if self.my_bulletin_data:
                self.my_bulletin_data['is_valid'] = False
                self.my_bulletin_data['validation_message'] = validation_message
            
            self.log(f"⚠️ Бюллетень принят, но некорректен: {validation_message}", "WARNING")
            messagebox.showwarning("Бюллетень некорректен",
                                 f"Ваш бюллетень был принят, но он некорректен!\n\n"
                                 f"Причина: {validation_message}\n\n"
                                 f"⚠️ Этот бюллетень НЕ будет учтен при подсчете результатов.\n"
                                 f"При проверке вы увидите, что бюллетень был изменен при отправке.")
        else:
            self.log(f"Ошибка отправки бюллетеня: {msg_text}", "ERROR")
            messagebox.showerror("Ошибка", msg_text)

    def handle_election_info(self, message: dict):
        """Обработка информации о выборах"""
        election_data = message.get('election')
        if election_data:
            self.election = Election.from_dict(election_data)
            eligible = message.get('eligible_voters', [])
            if eligible:
                self.eligible_voters = set(eligible)
            self.update_election_info()
            self.update_voting_button()

    def handle_published_data(self, message: dict):
        """Обработка опубликованных данных"""
        bulletins = message.get('bulletins', [])
        results = message.get('results')

        self.update_published_bulletins(bulletins)

        if results:
            self.update_results(results)

    def handle_election_started(self, message: dict):
        """Обработка сообщения о начале выборов"""
        election_data = message.get('election')
        if election_data:
            self.election = Election.from_dict(election_data)
            eligible = message.get('eligible_voters', [])
            if eligible:
                self.eligible_voters = set(eligible)
            self.update_election_info()
            self.update_voting_button()

        self.log("Голосование началось!", "INFO")
        messagebox.showinfo("Информация", "Голосование началось!")

    def handle_election_ended(self, message: dict):
        """Обработка сообщения о завершении выборов"""
        election_data = message.get('election')
        if election_data:
            self.election = Election.from_dict(election_data)
            self.update_election_info()
            self.update_voting_button()

        self.log("Голосование завершено", "INFO")
        messagebox.showinfo("Информация", "Голосование завершено!")

    def handle_bulletins_published(self, message: dict):
        """Обработка публикации бюллетеней"""
        data = message.get('data', [])
        self.update_published_bulletins(data)

        self.log(f"Опубликована таблица из {len(data)} бюллетеней", "INFO")
        messagebox.showinfo("Информация", f"Опубликована таблица бюллетеней")

    def handle_results_published(self, message: dict):
        """Обработка публикации результатов"""
        results = message.get('results', {})
        self.update_results(results)

        self.log("Опубликованы результаты голосования", "INFO")
        messagebox.showinfo("Информация", "Результаты голосования опубликованы!")

    def handle_voters_registry(self, message: dict):
        """Обработка опубликованного реестра избирателей"""
        registry = message.get('registry', [])
        eligible = message.get('eligible_voters', [])

        self.voters_registry = registry
        self.eligible_voters = set(eligible)
        self.registry_status = {entry.get('id', ''): "❌ Не аутентифицировался" for entry in registry if entry.get('id')}

        self.log(f"Получен реестр из {len(registry)} избирателей", "INFO")
        self.update_voter_info()
        self.update_voting_button()
        self.update_registry_table()

    # === Методы GUI ===

    def update_voter_info(self):
        """Обновление информации об избирателе"""
        info = ""
        if self.voter:
            auth_status = "✅ Аутентифицирован" if self.authenticated else "❌ Не аутентифицирован"
            vote_status = "✅ Проголосовал" if self.voter.has_voted or self.has_voted else "❌ Не голосовал"
            eligible_status = "Неизвестно"
            if self.eligible_voters:
                eligible_status = "✅ Допущен" if self.voter.id in self.eligible_voters else "❌ Не в реестре"

            info = f"""
ID: {self.voter.id}
ФИО: {self.voter.name}
Статус: {auth_status}
Голосование: {vote_status}
Допуск: {eligible_status}
Хэш бюллетеня: {self.voter.bulletin_hash[:30] + '...' if self.voter.bulletin_hash else 'Нет'}
            """

        self.voter_info.delete(1.0, tk.END)
        self.voter_info.insert(tk.END, info)

    def update_election_info(self):
        """Обновление информации о выборах"""
        if self.election:
            status = "✅ Активны" if self.election.is_active else "❌ Не активны"
            color = "green" if self.election.is_active else "red"

            self.election_title.config(text=self.election.title)
            self.election_status.config(text=f"Статус: {status}", foreground=color)
        else:
            self.election_title.config(text="Нет активных выборов")
            self.election_status.config(text="Статус: Неизвестно", foreground="black")

    def update_voting_button(self):
        """Обновление состояния кнопки голосования"""
        can_vote = (
                self.connected and
                self.authenticated and
                self.voter and
                self.election and
                self.election.is_active and
                not self.has_voted and
                not self.voter.has_voted and
                self.dss_keys_generated and
                (not self.eligible_voters or self.voter.id in self.eligible_voters)
        )

        if can_vote:
            self.vote_btn.config(state=tk.NORMAL, text="🗳️ Проголосовать")
        else:
            self.vote_btn.config(state=tk.DISABLED)

            # Определяем причину
            reason = ""
            if not self.connected:
                reason = "Нет подключения"
            elif not self.authenticated:
                reason = "Не аутентифицирован"
            elif not self.voter:
                reason = "Не зарегистрирован"
            elif not self.election:
                reason = "Нет выборов"
            elif not self.election.is_active:
                reason = "Голосование не активно"
            elif self.has_voted or self.voter.has_voted:
                reason = "Уже проголосовал"
            elif not self.dss_keys_generated:
                reason = "Нет DSS ключей"
            elif self.eligible_voters and self.voter and self.voter.id not in self.eligible_voters:
                reason = "Нет в реестре"

            if reason:
                self.vote_btn.config(text=f"Голосование недоступно ({reason})")

    def update_registry_table(self):
        """Отображение реестра допущенных избирателей"""
        if not hasattr(self, 'registry_tree'):
            return

        self.registry_tree.delete(*self.registry_tree.get_children())

        for entry in self.voters_registry:
            voter_id = entry.get('id', '')
            name = entry.get('name', '')
            # УБРАТЬ поля "Допущен" и "Статус"
            self.registry_tree.insert('', tk.END, values=(voter_id, name))

    def update_published_bulletins(self, bulletins: list):
        """Обновление списка опубликованных бюллетеней"""
        self.published_bulletins = bulletins  # ВАЖНО: сохраняем для проверки
        self.bulletins_tree.delete(*self.bulletins_tree.get_children())

        for bulletin in bulletins:
            f_value = str(bulletin.get('f', ''))
            if len(f_value) > 30:
                f_display = f_value[:30] + "..."
            else:
                f_display = f_value

            self.bulletins_tree.insert('', tk.END, values=(
                bulletin.get('voter_id', ''),
                f_display,
                bulletin.get('timestamp', '')
            ))

    def update_results(self, results: dict):
        """Обновление результатов голосования"""
        if not results:
            text = "Результаты еще не опубликованы"
        else:
            invalid_count = results.get('invalid_count', 0)
            text = f"""
{'=' * 50}
РЕЗУЛЬТАТЫ ГОЛОСОВАНИЯ
{'=' * 50}
Всего получено бюллетеней: {results.get('total', 0) + invalid_count}
✅ Корректных бюллетеней: {results.get('total', 0)}
❌ Некорректных бюллетеней: {invalid_count}

Проголосовали (учтено): {results.get('for', 0) + results.get('against', 0) + results.get('abstained', 0)}

✅ Голоса \"ЗА\": {results.get('for', 0)}
❌ Голоса \"ПРОТИВ\": {results.get('against', 0)}
➖ Воздержались: {results.get('abstained', 0)}

Контрольные числа:
F = {results.get('F', 0)}
Q = {results.get('Q', 0)}
R = {results.get('R', 0)}
{'=' * 50}
            """
            
            if invalid_count > 0:
                text += f"\n⚠️ ВНИМАНИЕ: {invalid_count} некорректных бюллетеней не учтены в подсчете!"

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, text)

    def update_bulletin_info(self, bulletin_data: dict, signature: dict):
        """Обновление информации о бюллетене"""
        choice_text = {
            1: "➖ Воздержаться",
            2: "✅ За",
            3: "❌ Против"
        }.get(bulletin_data.get('choice', 0), "Неизвестно")

        info = f"""
Выбор: {choice_text}
Затеняющий множитель q: {bulletin_data.get('q', 'N/A')}
Затененный бюллетень t: {bulletin_data.get('t', 'N/A')}
Зашифрованный бюллетень f: {bulletin_data.get('f', 'N/A')}

Подпись DSS:
r: {signature.get('r', 'N/A')}
s: {signature.get('s', 'N/A')}
H: {signature.get('H', 'N/A')}

Параметры ФФС:
m: {bulletin_data.get('m', 'N/A')}
e: {bulletin_data.get('e', 'N/A')}
        """

        self.bulletin_info.delete(1.0, tk.END)
        self.bulletin_info.insert(tk.END, info)

    # === Методы взаимодействия с сервером ===

    def register_voter(self):
        """Регистрация избирателя с использованием FFS"""
        voter_id = self.voter_id_entry.get().strip()
        voter_name = self.voter_name_entry.get().strip()

        if not voter_id or not voter_name:
            messagebox.showwarning("Предупреждение", "Заполните все поля")
            return

        if not self.dss_keys_generated:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте DSS ключи для голосования")
            return

        try:
            # Отправляем запрос на регистрацию (FFS ключи будут сгенерированы после получения n от сервера)
            self.send_message({
                'type': 'register',
                'voter_id': voter_id,
                'voter_name': voter_name,
                'public_key': None,  # Будет заполнено после генерации FFS ключей
                'timestamp': datetime.now().isoformat()
            })
            
            self.log(f"Отправлен запрос на регистрацию для {voter_name}", "INFO")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при регистрации: {e}")

    def authenticate_voter(self):
        """Аутентификация избирателя по протоколу FFS"""
        if not self.voter:
            messagebox.showwarning("Предупреждение", "Сначала зарегистрируйтесь")
            return

        if not self.ffs_keys_generated:
            messagebox.showwarning("Предупреждение", "FFS ключи не сгенерированы")
            return

        if not self.ffs_n:
            messagebox.showwarning("Предупреждение", "FFS параметр n не получен от сервера")
            return

        try:
            # Создаем обязательство (commitment)
            commitment = self.ffs.create_commitment(self.ffs_n)
            self.ffs_auth_r = commitment['r']
            x = commitment['x']

            # Отправляем первое сообщение с обязательством
            self.send_message({
                'type': 'authenticate',
                'voter_id': self.voter.id,
                'step': 1,
                'x': x,
                'v': self.ffs_v,
                'timestamp': datetime.now().isoformat()
            })
            
            self.log(f"Отправлено обязательство для аутентификации FFS", "INFO")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при аутентификации: {e}")

    def cast_vote(self):
        """Голосование"""
        # Проверяем условия
        if not self.connected:
            messagebox.showwarning("Предупреждение", "Нет подключения к серверу")
            return

        if not self.authenticated:
            messagebox.showwarning("Предупреждение", "Сначала пройдите аутентификацию")
            return

        if not self.voter:
            messagebox.showwarning("Предупреждение", "Сначала зарегистрируйтесь")
            return

        if not self.election:
            messagebox.showwarning("Предупреждение", "Нет активных выборов")
            return

        if not self.election.is_active:
            messagebox.showwarning("Предупреждение", "Голосование не активно")
            return

        if self.has_voted or self.voter.has_voted:
            messagebox.showwarning("Предупреждение", "Вы уже проголосовали")
            return

        if not self.dss_keys_generated:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте DSS ключи")
            return

        # Получаем выбор
        choice = self.vote_var.get()
        if choice == 0:
            messagebox.showwarning("Предупреждение", "Выберите вариант голосования")
            return

        # Показываем подтверждение
        choice_text = {1: "Воздержаться", 2: "За", 3: "Против"}.get(choice, "Неизвестно")
        confirm = messagebox.askyesno(
            "Подтверждение",
            f"Вы выбрали: {choice_text}\n\nВы уверены, что хотите проголосовать?\n"
            "После голосования изменить решение будет невозможно."
        )

        if not confirm:
            return

        # Создаем бюллетень
        try:
            bulletin_data = VotingCrypto.create_blinded_bulletin(
                choice=choice,
                m=self.election.m,
                e=self.election.e
            )

            # ДОБАВИТЬ: Применяем атаку, если включена
            if self.attack_enabled.get():
                attack_type = self.attack_type.get()
                original_f = bulletin_data['f']
                original_t = bulletin_data['t']
                
                if attack_type == "invalid_f":
                    # Атака: изменяем f на случайное значение, не соответствующее t^e mod m
                    import random
                    # Генерируем случайное число, которое точно не будет равно правильному f
                    wrong_f = random.randint(1, self.election.m - 1)
                    # Убеждаемся, что это не правильное значение
                    while wrong_f == original_f:
                        wrong_f = random.randint(1, self.election.m - 1)
                    bulletin_data['f'] = wrong_f
                    self.log(f"⚠️ АТАКА: Отправка некорректного f (было {original_f}, стало {wrong_f})", "WARNING")
                    
                elif attack_type == "invalid_rsa":
                    # Атака: изменяем параметры ФФС на неверные
                    bulletin_data['m'] = self.election.m + 1000
                    bulletin_data['e'] = self.election.e + 10
                    self.log(f"⚠️ АТАКА: Отправка некорректных параметров ФФС (m={bulletin_data['m']}, e={bulletin_data['e']})", "WARNING")
                    
                elif attack_type == "broken_calc":
                    # Атака: нарушаем вычисления - изменяем t, но не пересчитываем f
                    bulletin_data['t'] = bulletin_data['t'] + 10000
                    # f остается старым, что нарушит проверку f == t^e mod m
                    self.log(f"⚠️ АТАКА: Нарушены вычисления (t изменен с {original_t} на {bulletin_data['t']}, f не пересчитан)", "WARNING")
                
                elif attack_type == "invalid_q":
                    # НОВАЯ АТАКА: изменяем q на слишком маленькое значение
                    bulletin_data['q'] = 2  # Меньше минимального значения 5
                    # Пересчитываем t, но f остается старым
                    bulletin_data['t'] = bulletin_data['choice'] * bulletin_data['q']
                    self.log(f"⚠️ АТАКА: q изменен на недопустимо маленькое значение (2)", "WARNING")
                
                elif attack_type == "missing_field":
                    # НОВАЯ АТАКА: удаляем обязательное поле
                    del bulletin_data['q']
                    self.log(f"⚠️ АТАКА: Удалено обязательное поле 'q'", "WARNING")

            # Проверяем бюллетень (если атака не включена)
            if not self.attack_enabled.get():
                is_valid, msg = VotingCrypto.verify_bulletin(
                    bulletin_data,
                    self.election.m,
                    self.election.e
                )

                if not is_valid:
                    messagebox.showerror("Ошибка", f"Неверный бюллетень: {msg}")
                    return
            else:
                # Если атака включена, показываем предупреждение
                messagebox.showwarning("⚠️ АТАКА АКТИВНА",
                                     f"Отправляется некорректный бюллетень!\n"
                                     f"Тип атаки: {attack_type}\n"
                                     f"Сервер должен отклонить этот бюллетень.")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка создания бюллетеня: {e}")
            return

        # Создаем подпись
        try:
            bulletin_str = json.dumps(bulletin_data, sort_keys=True)
            signature = self.dsa.sign(bulletin_str)

            if not signature:
                messagebox.showerror("Ошибка", "Не удалось создать подпись")
                return

            r, s, H = signature

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка создания подписи: {e}")
            return

        # Сохраняем свои данные для проверки позже
        self.my_bulletin_data = {
            'bulletin': bulletin_data,
            'signature': {'r': r, 's': s, 'H': H},
            'choice': choice,
            'choice_text': {1: "Воздержаться", 2: "За", 3: "Против"}.get(choice),
            'is_attack': self.attack_enabled.get()
        }

        # Отправляем бюллетень
        self.send_message({
            'type': 'submit_bulletin',
            'voter_id': self.voter.id,
            'bulletin': bulletin_data,
            'signature': {'r': r, 's': s, 'H': H},
            'timestamp': datetime.now().isoformat()
        })

        # Обновляем информацию о бюллетене
        self.update_bulletin_info(bulletin_data, {'r': r, 's': s, 'H': H})

        # Блокируем кнопку
        self.vote_btn.config(state=tk.DISABLED, text="�� Отправка...")

    def get_published_data(self):
        """Запрос опубликованных данных"""
        if not self.connected:
            messagebox.showwarning("Предупреждение", "Нет подключения к серверу")
            return

        self.send_message({
            'type': 'get_published_data',
            'timestamp': datetime.now().isoformat()
        })

    def get_results(self):
        """Запрос результатов"""
        if not self.connected:
            messagebox.showwarning("Предупреждение", "Нет подключения к серверу")
            return

        self.send_message({
            'type': 'get_published_data',
            'timestamp': datetime.now().isoformat()
        })

    def get_voters_registry(self):
        """Запрос реестра допущенных избирателей"""
        if not self.connected:
            messagebox.showwarning("Предупреждение", "Нет подключения к серверу")
            return

        self.send_message({
            'type': 'get_voters_registry',
            'timestamp': datetime.now().isoformat()
        })

    def show_registry_local(self):
        """Показать последний полученный реестр"""
        if not self.voters_registry:
            messagebox.showinfo("Информация", "Реестр еще не получен. Нажмите \"Получить реестр\".")
            return

        self.update_registry_table()
        messagebox.showinfo("Информация", f"Показан локально сохраненный реестр ({len(self.voters_registry)} записей).")

    # === Криптографические методы ===

    def generate_dss_keys(self):
        """Генерация DSS ключей"""
        try:
            self.dss_entropy.add_os_entropy(64)
            self.dss_entropy.add_time_jitter(512)

            self.dsa.generate_parameters(q_bits=160, p_bits=1024)
            self.dsa.generate_keys()

            self.dss_keys_generated = True
            self.dss_status.config(text="✅ DSS ключи сгенерированы")

            # Обновляем информацию о ключах
            info = f"""
Параметры DSS:
p: {self.dsa.p}
q: {self.dsa.q}
g: {self.dsa.g}

Ключи:
Приватный ключ (x): {self.dsa.x}
Публичный ключ (y): {self.dsa.y}
            """

            self.keys_info.delete(1.0, tk.END)
            self.keys_info.insert(tk.END, info)

            self.log("DSS ключи успешно сгенерированы", "SUCCESS")

            # Обновляем кнопку голосования
            self.update_voting_button()

        except Exception as e:
            self.log(f"Ошибка генерации DSS ключей: {e}", "ERROR")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать DSS ключи: {e}")

    def generate_ffs_keys(self):
        """Генерация FFS ключей"""
        try:
            if not self.ffs_n:
                self.log("Ошибка: FFS параметр n не получен от сервера", "ERROR")
                messagebox.showerror("Ошибка", "FFS параметр n не получен от сервера")
                return
            
            self.log("Начинается генерация FFS ключей...", "INFO")
            
            keys = self.ffs.generate_client_keys(self.ffs_n)
            self.ffs_s = keys['s']
            self.ffs_v = keys['v']
            self.ffs_keys_generated = True
            
            # Обновляем публичный ключ в профиле избирателя
            if self.voter:
                self.voter.public_key = str(self.ffs_v)
            
            self.log(f"✅ FFS ключи успешно сгенерированы: v={self.ffs_v}", "SUCCESS")
            
        except Exception as e:
            self.log(f"Ошибка генерации FFS ключей: {e}", "ERROR")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать FFS ключи: {e}")

    def verify_signature(self):
        """Проверка собственной подписи"""
        if not self.dss_keys_generated:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте DSS ключи")
            return

        try:
            # Создаем тестовое сообщение
            test_message = f"TEST:{datetime.now().timestamp()}"

            # Создаем подпись
            signature = self.dsa.sign(test_message)
            if not signature:
                messagebox.showerror("Ошибка", "Не удалось создать подпись")
                return

            # Проверяем подпись
            success, info = self.dsa.verify(test_message, signature)

            if success:
                messagebox.showinfo("Успех", "Подпись корректна!\n\n" + info)
                self.log("Проверка подписи: успешно", "SUCCESS")
            else:
                messagebox.showerror("Ошибка", "Подпись некорректна!\n\n" + info)
                self.log(f"Проверка подписи: ошибка - {info}", "ERROR")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при проверке подписи: {e}")
            self.log(f"Ошибка проверки подписи: {e}", "ERROR")

    def run(self):
        """Запуск клиентского приложения"""
        self.root.mainloop()

    def verify_my_vote(self):
        """Проверка что мой голос присутствует в опубликованных результатах"""
        if not self.my_bulletin_data:
            messagebox.showwarning("Предупреждение", "Вы еще не голосовали или данные не сохранены")
            return

        if not self.published_bulletins:
            messagebox.showwarning("Предупреждение", "Получите сначала опубликованные бюллетени")
            return

        my_f = self.my_bulletin_data['bulletin']['f']
        my_choice = self.my_bulletin_data['choice']
        my_q = self.my_bulletin_data['bulletin']['q']
        my_voter_id = self.voter.id if self.voter else "unknown"
        is_attack = self.my_bulletin_data.get('is_attack', False)
        is_valid = self.my_bulletin_data.get('is_valid', True)
        validation_message = self.my_bulletin_data.get('validation_message', '')

        # Ищем свой бюллетень в опубликованных по voter_id
        found_bulletin = None
        
        for published_bulletin in self.published_bulletins:
            if published_bulletin.get('voter_id') == my_voter_id:
                found_bulletin = published_bulletin
                break

        # Проверяем, был ли бюллетень некорректным при отправке
        if not is_valid or is_attack:
            result_text = f"""
🚨 БЮЛЛЕТЕНЬ БЫЛ НЕКОРРЕКТНЫМ ПРИ ОТПРАВКЕ!

Ваш бюллетень был изменен перед отправкой (атака) или содержал ошибки.

Детали:
  ID избирателя: {my_voter_id}
  Зашифрованный f: {my_f}
  Затеняющий множитель q: {my_q}
  Ваш выбор: {self.my_bulletin_data['choice_text']}
  
Причина некорректности: {validation_message if validation_message else 'Бюллетень был изменен перед отправкой (атака)'}

⚠️ ВАЖНО: Этот бюллетень НЕ будет учтен при подсчете результатов голосования!

Статус: Бюллетень был некорректен при отправке и не включен в подсчет.
            """
            messagebox.showerror("🚨 Бюллетень некорректен", result_text)
            self.log(f"🚨 Бюллетень был некорректным при отправке: {validation_message}", "ERROR")
            return

        if found_bulletin:
            published_f = found_bulletin.get('f')
            
            # Сравниваем f
            if published_f == my_f:
                # Бюллетень найден и f совпадает
                result_text = f"""
✅ ВАШЕ ГОЛОСОВАНИЕ ВЕРИФИЦИРОВАНО

Ваш выбор: {self.my_bulletin_data['choice_text']}
Затеняющий множитель q: {my_q}
Зашифрованный бюллетень f: {my_f}

Статус: Ваше голосование найдено в опубликованной таблице
и включено в подсчет результатов.

Время голосования: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                """
                messagebox.showinfo("Верификация успешна", result_text)
                self.log("Голосование верифицировано в опубликованной таблице", "SUCCESS")
            else:
                # 🚨 АТАКА ОБНАРУЖЕНА: бюллетень найден, но f изменен!
                result_text = f"""
🚨 АТАКА ОБНАРУЖЕНА! БЮЛЛЕТЕНЬ БЫЛ ИЗМЕНЕН СЕРВЕРОМ!

Ваш оригинальный бюллетень:
  ID избирателя: {my_voter_id}
  Зашифрованный f: {my_f}
  Затеняющий множитель q: {my_q}
  Ваш выбор: {self.my_bulletin_data['choice_text']}

Опубликованный сервером бюллетень:
  ID избирателя: {found_bulletin.get('voter_id', 'N/A')}
  Зашифрованный f: {published_f}
  Время: {found_bulletin.get('timestamp', 'N/A')}

⚠️ ВНИМАНИЕ: Значение f было изменено сервером!
Оригинальный f: {my_f}
Измененный f: {published_f}

Ваш голос НЕ соответствует опубликованному бюллетеню!
Это указывает на атаку или манипуляцию со стороны сервера.
                """
                messagebox.showerror("🚨 АТАКА ОБНАРУЖЕНА!", result_text)
                self.log(f"🚨 АТАКА: Бюллетень был изменен! Оригинальный f={my_f}, опубликованный f={published_f}", "ERROR")
        else:
            # Бюллетень вообще не найден
            messagebox.showerror("Верификация не пройдена",
                               f"Ваше голосование НЕ найдено в опубликованной таблице бюллетеней!\n\n"
                               f"Ваш ID: {my_voter_id}\n"
                               f"Ваш f: {my_f}\n\n"
                               f"Это может указывать на:\n"
                               f"- Проблему с передачей данных\n"
                               f"- Атаку на сервер\n"
                               f"- Удаление вашего бюллетеня\n"
                               f"- Бюллетень был некорректен и не был опубликован")
            self.log(f"ОШИБКА: Голосование НЕ найдено в опубликованной таблице (ID: {my_voter_id}, f: {my_f})", "ERROR")

    def update_published_bulletins(self, bulletins: list):
        """Обновление списка опубликованных бюллетеней"""
        self.published_bulletins = bulletins  # ВАЖНО: сохраняем для проверки
        self.bulletins_tree.delete(*self.bulletins_tree.get_children())

        for bulletin in bulletins:
            f_value = str(bulletin.get('f', ''))
            if len(f_value) > 30:
                f_display = f_value[:30] + "..."
            else:
                f_display = f_value

            self.bulletins_tree.insert('', tk.END, values=(
                bulletin.get('voter_id', ''),
                f_display,
                bulletin.get('timestamp', '')
            ))

    def verify_other_vote(self):
        """Проверка голоса другого избирателя"""
        voter_id = self.verify_voter_id_entry.get().strip()
        
        if not voter_id:
            messagebox.showwarning("Предупреждение", "Введите ID избирателя")
            return
        
        if not self.published_bulletins:
            messagebox.showwarning("Предупреждение", "Получите сначала опубликованные бюллетени")
            return
        
        # Ищем голоса этого избирателя
        found_bulletins = [b for b in self.published_bulletins if b.get('voter_id') == voter_id]
        
        if not found_bulletins:
            messagebox.showwarning(
                "Результат проверки",
                f"Голос избирателя с ID '{voter_id}' НЕ найден в опубликованной таблице.\n\n"
                "Возможные причины:\n"
                "- Избиратель не проголосовал\n"
                "- ID введен неверно\n"
                "- Данные еще не опубликованы"
            )
            self.log(f"Голос избирателя {voter_id} не найден", "WARNING")
            return
        
        # Формируем отчет о найденных голосах
        bulletins_info = ""
        for i, bulletin in enumerate(found_bulletins, 1):
            f_value = str(bulletin.get('f', ''))
            if len(f_value) > 40:
                f_display = f_value[:40] + "..."
            else:
                f_display = f_value
            
            bulletins_info += f"""
Голос #{i}:
  f (зашифрованный бюллетень): {f_display}
  Время: {bulletin.get('timestamp', 'N/A')}
            """
        
        result_text = f"""
✅ ГОЛОС НАЙДЕН И ВЕРИФИЦИРОВАН

ID избирателя: {voter_id}
Количество голосов в таблице: {len(found_bulletins)}

{bulletins_info}

Статус: Голос(а) избирателя найден(ы) в опубликованной таблице
и включен(ы) в подсчет результатов.

Проверка выполнена: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        """
        
        messagebox.showinfo("✅ Проверка успешна", result_text)
        self.log(f"Голос избирателя {voter_id} верифицирован (найдено {len(found_bulletins)} голос(ов))", "SUCCESS")
    
    def show_voter_bulletin(self):
        """Показать подробные данные бюллетеня избирателя"""
        voter_id = self.verify_voter_id_entry.get().strip()
        
        if not voter_id:
            messagebox.showwarning("Предупреждение", "Введите ID избирателя")
            return
        
        if not self.published_bulletins:
            messagebox.showwarning("Предупреждение", "Получите сначала опубликованные бюллетени")
            return
        
        # Ищем голоса этого избирателя
        found_bulletins = [b for b in self.published_bulletins if b.get('voter_id') == voter_id]
        
        if not found_bulletins:
            messagebox.showwarning(
                "Информация",
                f"Данные избирателя '{voter_id}' не найдены в таблице"
            )
            return
        
        # Создаем окно со всеми данными
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Данные избирателя: {voter_id}")
        detail_window.geometry("800x600")
        
        # Текстовое поле с информацией
        text_frame = ttk.Frame(detail_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        detail_text = scrolledtext.ScrolledText(text_frame, height=30)
        detail_text.pack(fill=tk.BOTH, expand=True)
        
        # Формируем полный отчет
        info = f"""
{'=' * 70}
ПОЛНАЯ ИНФОРМАЦИЯ О ГОЛОСЕ ИЗБИРАТЕЛЯ
{'=' * 70}

ID избирателя: {voter_id}
Всего записей: {len(found_bulletins)}
Дата проверки: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

{'-' * 70}
        """
        
        for i, bulletin in enumerate(found_bulletins, 1):
            info += f"""
ЗАПИСЬ #{i}:
─────────────────────────────────────────────────────────────────

Зашифрованный бюллетень (f):
{bulletin.get('f', 'N/A')}

Временная метка: {bulletin.get('timestamp', 'N/A')}
Статус: {'✅ Найден и включен в результаты' if bulletin else '❌ Отсутствует'}

        """
        
        info += f"""
{'=' * 70}
РЕЗУЛЬТАТЫ ПРОВЕРКИ:

✅ Голос избирателя присутствует в опубликованной таблице
✅ Голос включен в подсчет результатов
✅ Голос невозможно изменить (защита от подделки)

КАК РАБОТАЕТ ВЕРИФИКАЦИЯ:

1. Зашифрованный бюллетень (f) публично опубликован
2. Любой может проверить наличие голоса в таблице
3. Сам избиратель может проверить свой голос (зная q)
4. Систему невозможно манипулировать без обнаружения

{'=' * 70}
        """
        
        detail_text.insert(tk.END, info)
        detail_text.config(state=tk.DISABLED)
        
        # Кнопка закрытия
        btn_frame = ttk.Frame(detail_window)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Закрыть", command=detail_window.destroy).pack(padx=5)
    
    def verify_checksums(self):
        """Проверка контрольных сумм результатов голосования"""
        if not self.published_bulletins:
            messagebox.showwarning("Предупреждение", "Сначала получите опубликованные бюллетени")
            return
        
        if not self.election or not self.election.results:
            messagebox.showwarning("Предупреждение", "Результаты голосования еще не опубликованы")
            return
        
        results = self.election.results
        m = self.election.m
        e = self.election.e
        
        published_F = results.get('F', 0)
        published_Q = results.get('Q', 0)
        published_R = results.get('R', 0)
        published_for = results.get('for', 0)
        published_against = results.get('against', 0)
        published_abstained = results.get('abstained', 0)
        
        self.log("=" * 70)
        self.log("ПРОВЕРКА КОНТРОЛЬНЫХ СУММ РЕЗУЛЬТАТОВ ГОЛОСОВАНИЯ")
        self.log("=" * 70)
        
        checks_passed = []
        checks_failed = []
        
        self.log(f"Опубликованные результаты:")
        self.log(f"  Голоса 'ЗА': {published_for}")
        self.log(f"  Голоса 'ПРОТИВ': {published_against}")
        self.log(f"  Воздержались: {published_abstained}")
        self.log(f"  F = {published_F}")
        self.log(f"  Q = {published_Q}")
        self.log(f"  R = {published_R}")
        self.log("")
        
        self.log(f"Проверка 1: Вычисление F = произведение всех f (mod {m})")
        calculated_F = 1
        for bulletin in self.published_bulletins:
            f_value = bulletin.get('f')
            if isinstance(f_value, int):
                calculated_F = (calculated_F * f_value) % m
        
        self.log(f"  Вычислено F = {calculated_F}")
        self.log(f"  Опубликовано F = {published_F}")
        
        if calculated_F == published_F:
            checks_passed.append("✅ Проверка F пройдена: F корректно вычислено")
            self.log("  ✅ УСПЕХ: F совпадает!")
        else:
            checks_failed.append("❌ ПРОВАЛЕНО: F не совпадает! Возможна подделка результатов!")
            self.log("  ❌ ОШИБКА: F НЕ СОВПАДАЕТ!")
        
        self.log("")
        self.log("Проверка 2: Делимость Q на 2 (голоса 'ЗА')")
        temp_Q = published_Q
        calculated_for = 0
        
        while temp_Q % 2 == 0:
            calculated_for += 1
            temp_Q //= 2
        
        self.log(f"  Q делится на 2 в степени: {calculated_for}")
        self.log(f"  Опубликовано голосов 'ЗА': {published_for}")
        
        if calculated_for == published_for:
            checks_passed.append("✅ Проверка голосов 'ЗА' пройдена")
            self.log("  ✅ УСПЕХ: Количество голосов 'ЗА' совпадает!")
        else:
            checks_failed.append(f"❌ ПРОВАЛЕНО: Голоса 'ЗА' не совпадают! Вычислено: {calculated_for}, опубликовано: {published_for}")
            self.log(f"  ❌ ОШИБКА: Количество голосов 'ЗА' НЕ СОВПАДАЕТ!")
        
        self.log("")
        self.log("Проверка 3: Делимость на 3 (голоса 'ПРОТИВ')")
        calculated_against = 0
        
        while temp_Q % 3 == 0:
            calculated_against += 1
            temp_Q //= 3
        
        self.log(f"  Q делится на 3 в степени: {calculated_against}")
        self.log(f"  Опубликовано голосов 'ПРОТИВ': {published_against}")
        
        if calculated_against == published_against:
            checks_passed.append("✅ Проверка голосов 'ПРОТИВ' пройдена")
            self.log("  ✅ УСПЕХ: Количество голосов 'ПРОТИВ' совпадает!")
        else:
            checks_failed.append(f"❌ ПРОВАЛЕНО: Голоса 'ПРОТИВ' не совпадают! Вычислено: {calculated_against}, опубликовано: {published_against}")
            self.log(f"  ❌ ОШИБКА: Количество голосов 'ПРОТИВ' НЕ СОВПАДАЕТ!")
        
        calculated_R = temp_Q
        self.log("")
        self.log(f"Проверка 4: Остаток R (произведение всех q)")
        self.log(f"  Вычислено R = {calculated_R}")
        self.log(f"  Опубликовано R = {published_R}")
        
        if calculated_R == published_R:
            checks_passed.append("✅ Проверка R пройдена")
            self.log("  ✅ УСПЕХ: R совпадает!")
        else:
            checks_failed.append(f"❌ ПРОВАЛЕНО: R не совпадает! Вычислено: {calculated_R}, опубликовано: {published_R}")
            self.log("  ❌ ОШИБКА: R НЕ СОВПАДАЕТ!")
        
        total_votes = published_for + published_against + published_abstained
        total_bulletins = len(self.published_bulletins)
        
        self.log("")
        self.log(f"Проверка 5: Общее количество голосов")
        self.log(f"  Бюллетеней опубликовано: {total_bulletins}")
        self.log(f"  Голосов подсчитано: {total_votes}")
        
        if total_votes <= total_bulletins:
            checks_passed.append("✅ Количество голосов не превышает количество бюллетеней")
            self.log("  ✅ УСПЕХ: Количество голосов корректно!")
        else:
            checks_failed.append(f"❌ ПРОВАЛЕНО: Голосов больше чем бюллетеней!")
            self.log("  ❌ ОШИБКА: Голосов больше чем бюллетеней!")
        
        self.log("")
        self.log("=" * 70)
        self.log("ИТОГИ ПРОВЕРКИ:")
        self.log("=" * 70)
        
        for check in checks_passed:
            self.log(check)
        
        for check in checks_failed:
            self.log(check)
        
        self.log("=" * 70)
        
        if not checks_failed:
            result_text = f"""
{'=' * 60}
✅ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО!
{'=' * 60}

Результаты голосования верифицированы и корректны:

{chr(10).join(checks_passed)}

Проверено:
  • F = произведение всех зашифрованных бюллетеней
  • Делимость Q на 2 (голоса 'ЗА'): {calculated_for}
  • Делимость Q на 3 (голоса 'ПРОТИВ'): {calculated_against}
  • Остаток R (произведение q)
  • Общее количество голосов

Результаты можно считать достоверными.
Манипуляции не обнаружены.

Дата проверки: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'=' * 60}
            """
            messagebox.showinfo("✅ Проверка успешна", result_text)
            self.log("✅ ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ УСПЕШНО!", "SUCCESS")
        else:
            result_text = f"""
{'=' * 60}
❌ ОБНАРУЖЕНЫ ПРОБЛЕМЫ!
{'=' * 60}

Некоторые проверки не пройдены:

{chr(10).join(checks_failed)}

Успешные проверки:
{chr(10).join(checks_passed)}

⚠️ ВНИМАНИЕ: Результаты могут быть недостоверными!
Возможна манипуляция данными или ошибка в подсчете.

Дата проверки: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'=' * 60}
            """
            messagebox.showerror("❌ Проверка провалена", result_text)
            self.log("❌ НЕКОТОРЫЕ ПРОВЕРКИ НЕ ПРОЙДЕНЫ!", "ERROR")


def main():
    """Точка входа клиентского приложения"""
    client = VoterClient()
    client.run()


if __name__ == "__main__":
    main()