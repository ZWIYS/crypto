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
from common.crypto import VotingCrypto
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

        # Криптография
        self.dss_entropy = EntropyCollector()
        self.dsa = DSA(self.dss_entropy)
        self.dss_keys_generated = False

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

            self.update_voter_info()
            self.log(f"Регистрация успешна: {msg_text}", "SUCCESS")

            # Автоматически аутентифицируемся
            self.root.after(1000, self.authenticate_voter)
        else:
            self.log(f"Ошибка регистрации: {msg_text}", "ERROR")
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

            self.update_voter_info()
            self.update_election_info()
            self.update_voting_button()

            self.log(f"Аутентификация успешна: {msg_text}", "SUCCESS")
            messagebox.showinfo("Успех", "Аутентификация успешна!\nТеперь вы можете проголосовать.")
        else:
            self.log(f"Ошибка аутентификации: {msg_text}", "ERROR")
            messagebox.showerror("Ошибка", msg_text)

    def handle_submit_response(self, message: dict):
        """Обработка ответа на отправку бюллетеня"""
        success = message.get('success', False)
        msg_text = message.get('message', '')

        if success:
            self.has_voted = True
            if self.voter:
                self.voter.has_voted = True

            self.update_voter_info()
            self.update_voting_button()

            bulletin_id = message.get('bulletin_id', 0)

            self.log(f"Бюллетень принят (ID: {bulletin_id})", "SUCCESS")
            messagebox.showinfo("Успех", "Ваш голос успешно зарегистрирован!")
        else:
            self.log(f"Ошибка отправки бюллетеня: {msg_text}", "ERROR")
            messagebox.showerror("Ошибка", msg_text)

    def handle_election_info(self, message: dict):
        """Обработка информации о выборах"""
        election_data = message.get('election')
        if election_data:
            self.election = Election.from_dict(election_data)
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

    # === Методы GUI ===

    def update_voter_info(self):
        """Обновление информации об избирателе"""
        info = ""
        if self.voter:
            auth_status = "✅ Аутентифицирован" if self.authenticated else "❌ Не аутентифицирован"
            vote_status = "✅ Проголосовал" if self.voter.has_voted or self.has_voted else "❌ Не голосовал"

            info = f"""
ID: {self.voter.id}
ФИО: {self.voter.name}
Статус: {auth_status}
Голосование: {vote_status}
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
                self.dss_keys_generated
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

            if reason:
                self.vote_btn.config(text=f"Голосование недоступно ({reason})")

    def update_published_bulletins(self, bulletins: list):
        """Обновление списка опубликованных бюллетеней"""
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
            text = f"""
{'=' * 50}
РЕЗУЛЬТАТЫ ГОЛОСОВАНИЯ
{'=' * 50}
Всего избирателей: {results.get('total', 0)}
Проголосовали: {results.get('for', 0) + results.get('against', 0) + results.get('abstained', 0)}

✅ Голоса \"ЗА\": {results.get('for', 0)}
❌ Голоса \"ПРОТИВ\": {results.get('against', 0)}
➖ Воздержались: {results.get('abstained', 0)}

Контрольные числа:
F = {results.get('F', 0)}
Q = {results.get('Q', 0)}
R = {results.get('R', 0)}
{'=' * 50}
            """

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

Параметры RSA:
m: {bulletin_data.get('m', 'N/A')}
e: {bulletin_data.get('e', 'N/A')}
        """

        self.bulletin_info.delete(1.0, tk.END)
        self.bulletin_info.insert(tk.END, info)

    # === Методы взаимодействия с сервером ===

    def register_voter(self):
        """Регистрация избирателя"""
        voter_id = self.voter_id_entry.get().strip()
        voter_name = self.voter_name_entry.get().strip()

        if not voter_id or not voter_name:
            messagebox.showwarning("Предупреждение", "Заполните все поля")
            return

        if not self.dss_keys_generated:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте DSS ключи")
            return

        # Создаем подпись
        reg_message = f"REGISTER:{voter_id}:{voter_name}:{datetime.now().timestamp()}"

        try:
            signature = self.dsa.sign(reg_message)
            if not signature:
                messagebox.showerror("Ошибка", "Не удалось создать подпись")
                return

            r, s, H = signature

            # Отправляем запрос
            self.send_message({
                'type': 'register',
                'voter_id': voter_id,
                'voter_name': voter_name,
                'public_key': str(self.dsa.y) if self.dsa.y else None,
                'signature': {'r': r, 's': s, 'H': H},
                'timestamp': datetime.now().isoformat()
            })

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при регистрации: {e}")

    def authenticate_voter(self):
        """Аутентификация избирателя"""
        if not self.voter:
            messagebox.showwarning("Предупреждение", "Сначала зарегистрируйтесь")
            return

        # Создаем подпись
        auth_message = f"AUTH:{self.voter.id}:{datetime.now().timestamp()}"

        try:
            signature = self.dsa.sign(auth_message)
            if not signature:
                messagebox.showerror("Ошибка", "Не удалось создать подпись")
                return

            r, s, H = signature

            # Отправляем запрос
            self.send_message({
                'type': 'authenticate',
                'voter_id': self.voter.id,
                'signature': {'r': r, 's': s, 'H': H},
                'timestamp': datetime.now().isoformat()
            })

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

            # Проверяем бюллетень
            is_valid, msg = VotingCrypto.verify_bulletin(
                bulletin_data,
                self.election.m,
                self.election.e
            )

            if not is_valid:
                messagebox.showerror("Ошибка", f"Неверный бюллетень: {msg}")
                return

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
        self.vote_btn.config(state=tk.DISABLED, text="📤 Отправка...")

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


def main():
    """Точка входа клиентского приложения"""
    client = VoterClient()
    client.run()


if __name__ == "__main__":
    main()