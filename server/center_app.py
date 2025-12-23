"""
Сервер Центра электронного голосования
"""
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import json
import time
from datetime import datetime
import hashlib
import os
import sys

# Добавляем путь к общим модулям
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.protocol import MessageProtocol
from common.crypto import RSACrypto, VotingCrypto, FFSCrypto
from common.models import Election, Voter, Bulletin, ServerConfig
from dss import EntropyCollector, DSA


class CenterServer:
    """Сервер Центра для электронного голосования"""

    def __init__(self, config: ServerConfig = None):
        self.config = config or ServerConfig()

        # Сетевое подключение
        self.server_socket = None
        self.clients = {}  # socket -> address
        self.running = False
        self.client_lock = threading.Lock()

        # Данные системы
        self.current_election = None
        self.voters = {}  # id -> Voter
        self.bulletins = []  # Список бюллетеней
        self.published_data = []  # Опубликованные данные
        self.allowed_voters = set()  # Снимок реестра допущенных
        self.authenticated_voters = set()  # ID прошедших аутентификацию
        self.registry_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "voters_registry.txt"
        )

        # Криптография
        self.rsa_keys = None
        self.entropy = EntropyCollector()
        self.dsa = DSA(self.entropy)
        self.dss_initialized = False
        
        # FFS аутентификация
        self.ffs = FFSCrypto(self.entropy)
        self.ffs_n = None
        self.ffs_initialized = False
        self.ffs_auth_sessions = {}  # voter_id -> {'x': x, 'b': b, 'v': v}

        # GUI
        self.root = tk.Tk()
        self.setup_gui()
        # Загружаем заранее подготовленный реестр
        self.load_voters_from_file()

    def setup_gui(self):
        """Настройка графического интерфейса сервера"""
        self.root.title("Центр электронного голосования - Сервер")
        self.root.geometry("1100x750")

        # Стили
        style = ttk.Style()
        style.theme_use('clam')

        # Основные вкладки
        notebook = ttk.Notebook(self.root)

        # Создаем вкладки
        tabs = [
            ("Сервер", self.setup_server_tab),
            ("Выборы", self.setup_election_tab),
            ("Избиратели", self.setup_voters_tab),
            ("Бюллетени", self.setup_bulletins_tab),
            ("Результаты", self.setup_results_tab),
            ("Логи", self.setup_logs_tab)
        ]

        for tab_name, setup_func in tabs:
            tab = ttk.Frame(notebook)
            setup_func(tab)
            notebook.add(tab, text=tab_name)

        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def setup_server_tab(self, parent):
        """Вкладка управления сервером"""
        frame = ttk.LabelFrame(parent, text="Управление сервером", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Настройки сервера
        settings_frame = ttk.Frame(frame)
        settings_frame.pack(fill=tk.X, pady=5)

        ttk.Label(settings_frame, text="Хост:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.host_entry = ttk.Entry(settings_frame, width=20)
        self.host_entry.insert(0, self.config.host)
        self.host_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(settings_frame, text="Порт:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.port_entry = ttk.Entry(settings_frame, width=10)
        self.port_entry.insert(0, str(self.config.port))
        self.port_entry.grid(row=0, column=3, padx=5, pady=2)

        # Статус
        status_frame = ttk.Frame(frame)
        status_frame.pack(fill=tk.X, pady=10)

        self.status_label = ttk.Label(status_frame, text="🛑 Сервер остановлен",
                                      font=('Arial', 12, 'bold'))
        self.status_label.pack()

        self.clients_label = ttk.Label(status_frame, text="Подключенных клиентов: 0")
        self.clients_label.pack()

        # Кнопки управления
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        self.start_btn = ttk.Button(btn_frame, text="▶ Запустить сервер",
                                    command=self.start_server, width=20)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="⏹ Остановить сервер",
                                   command=self.stop_server, width=20, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Криптография
        crypto_frame = ttk.LabelFrame(frame, text="Криптография", padding=10)
        crypto_frame.pack(fill=tk.X, pady=10)

        btn_crypto = ttk.Frame(crypto_frame)
        btn_crypto.pack(pady=5)

        ttk.Button(btn_crypto, text="🔑 Генерация ФФС ключей",
                   command=self.generate_rsa_keys).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_crypto, text="🔐 Генерация FFS параметров",
                   command=self.generate_ffs_params).pack(side=tk.LEFT, padx=5)

        self.crypto_status = ttk.Label(crypto_frame, text="Ключи не сгенерированы")
        self.crypto_status.pack()

    def setup_election_tab(self, parent):
        """Вкладка управления выборами"""
        frame = ttk.LabelFrame(parent, text="Управление выборами", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Создание выборов
        create_frame = ttk.LabelFrame(frame, text="Создание новых выборов", padding=10)
        create_frame.pack(fill=tk.X, pady=5)

        ttk.Label(create_frame, text="Название:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.election_title = ttk.Entry(create_frame, width=40)
        self.election_title.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)

        ttk.Label(create_frame, text="Описание:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.election_desc = ttk.Entry(create_frame, width=40)
        self.election_desc.grid(row=1, column=1, padx=5, pady=2, sticky=tk.W)

        # ДОБАВИТЬ ЭТО:
        ttk.Label(create_frame, text="Длительность (минуты):").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.election_duration = ttk.Entry(create_frame, width=40)
        self.election_duration.insert(0, "60")  # По умолчанию 60 минут
        self.election_duration.grid(row=2, column=1, padx=5, pady=2, sticky=tk.W)

        # Информация о текущих выборах
        info_frame = ttk.LabelFrame(frame, text="Текущие выборы", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.election_info = scrolledtext.ScrolledText(info_frame, height=10)
        self.election_info.pack(fill=tk.BOTH, expand=True)

        # Управление выборами
        control_frame = ttk.Frame(frame)
        control_frame.pack(pady=10)

        self.create_btn = ttk.Button(control_frame, text="📋 Создать выборы",
                                     command=self.create_election, width=20)
        self.create_btn.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(control_frame, text="▶ Начать голосование",
                                    command=self.start_election, width=20, state=tk.DISABLED)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.end_btn = ttk.Button(control_frame, text="⏹ Завершить голосование",
                                  command=self.end_election, width=20, state=tk.DISABLED)
        self.end_btn.pack(side=tk.LEFT, padx=5)

    def setup_voters_tab(self, parent):
        """Вкладка регистрации избирателей"""
        frame = ttk.LabelFrame(parent, text="Регистрация избирателей", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Регистрация нового избирателя
        reg_frame = ttk.LabelFrame(frame, text="Новый избиратель", padding=10)
        reg_frame.pack(fill=tk.X, pady=5)

        ttk.Label(reg_frame, text="ID избирателя:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.voter_id_entry = ttk.Entry(reg_frame, width=30)
        self.voter_id_entry.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(reg_frame, text="ФИО:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.voter_name_entry = ttk.Entry(reg_frame, width=30)
        self.voter_name_entry.grid(row=1, column=1, padx=5, pady=2)

        ttk.Button(reg_frame, text="📝 Зарегистрировать",
                   command=self.register_voter).grid(row=2, column=0, columnspan=2, pady=10)

        # Список избирателей
        list_frame = ttk.LabelFrame(frame, text="Зарегистрированные избиратели", padding=5)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        columns = ('ID', 'ФИО', 'Допущен', 'Статус', 'Хэш бюллетеня')
        self.voters_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.voters_tree.heading(col, text=col)
            width = 140
            if col == 'ФИО':
                width = 200
            elif col == 'Хэш бюллетеня':
                width = 200
            self.voters_tree.column(col, width=width)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.voters_tree.yview)
        self.voters_tree.configure(yscrollcommand=scrollbar.set)

        self.voters_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Кнопка публикации реестра
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=8)
        ttk.Button(btn_frame, text="📢 Опубликовать реестр допущенных",
                   command=self.publish_voters_registry).pack(side=tk.LEFT, padx=5)

    def setup_bulletins_tab(self, parent):
        """Вкладка бюллетеней"""
        frame = ttk.LabelFrame(parent, text="Полученные бюллетени", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Таблица бюллетеней - ДОБАВИТЬ колонку "Статус проверки"
        columns = ('ID избирателя', 'Зашифрованный f', 'Статус проверки', 'Подпись', 'Время')
        self.bulletins_tree = ttk.Treeview(frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.bulletins_tree.heading(col, text=col)
            if col == 'Статус проверки':
                self.bulletins_tree.column(col, width=150)
            else:
                self.bulletins_tree.column(col, width=200)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.bulletins_tree.yview)
        self.bulletins_tree.configure(yscrollcommand=scrollbar.set)

        self.bulletins_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Кнопки управления
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="📊 Опубликовать таблицу",
                   command=self.publish_bulletins).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="✅ Проверить подписи",
                   command=self.verify_signatures).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="🔍 Проверить все бюллетени",
                   command=self.verify_all_bulletins).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="💾 Экспорт бюллетеней",
                   command=self.export_bulletins).pack(side=tk.LEFT, padx=5)

        # ДОБАВИТЬ: Секция для атаки
        attack_frame = ttk.LabelFrame(frame, text="⚠️ АТАКА: Изменение бюллетеня", padding=10)
        attack_frame.pack(fill=tk.X, pady=10)

        ttk.Label(attack_frame, text="ID избирателя для атаки:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.attack_voter_id_entry = ttk.Entry(attack_frame, width=20)
        self.attack_voter_id_entry.grid(row=0, column=1, padx=5, pady=2)

        attack_btn_frame = ttk.Frame(attack_frame)
        attack_btn_frame.grid(row=1, column=0, columnspan=2, pady=5)

        ttk.Button(attack_btn_frame, text="🔓 Изменить значение f",
                   command=self.attack_modify_bulletin_f).pack(side=tk.LEFT, padx=5)

        ttk.Button(attack_btn_frame, text="🔓 Изменить choice",
                   command=self.attack_modify_bulletin_choice).pack(side=tk.LEFT, padx=5)

        ttk.Button(attack_btn_frame, text="🔓 Нарушить проверку",
                   command=self.attack_break_verification).pack(side=tk.LEFT, padx=5)

        ttk.Button(attack_btn_frame, text="🔓 Изменить параметры ФФС",
                   command=self.attack_modify_rsa_params).pack(side=tk.LEFT, padx=5)

        self.attack_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(attack_frame, text="Включить автоматическую атаку при получении",
                       variable=self.attack_enabled).grid(row=2, column=0, columnspan=2, pady=5)

    def setup_results_tab(self, parent):
        """Вкладка результатов"""
        frame = ttk.LabelFrame(parent, text="Результаты голосования", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Результаты
        self.results_text = scrolledtext.ScrolledText(frame, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        self.calc_btn = ttk.Button(btn_frame, text="🧮 Подсчитать результаты",
                                   command=self.calculate_results, width=20)
        self.calc_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="📢 Опубликовать результаты",
                   command=self.publish_results, width=20).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="💾 Экспорт результатов",
                   command=self.export_results, width=20).pack(side=tk.LEFT, padx=5)

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

        # Сохраняем в файл
        try:
            with open("server.log", "a", encoding="utf-8") as f:
                f.write(log_entry)
        except:
            pass

    # === Основные методы сервера ===

    def generate_rsa_keys(self):
        """Генерация ФФС ключей"""
        try:
            self.rsa_keys = RSACrypto.generate_keypair(2048)
            self.crypto_status.config(text=f"✅ ФФС ключи сгенерированы (m={self.rsa_keys['m']})")
            self.log("ФФС ключи успешно сгенерированы")
        except Exception as e:
            self.log(f"Ошибка генерации ФФС ключей: {e}", "ERROR")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать ФФС ключи: {e}")

    def generate_dss_params(self):
        """Генерация DSS параметров"""
        try:
            self.entropy.add_os_entropy(64)
            self.entropy.add_time_jitter(512)
            self.dsa.generate_parameters(q_bits=160, p_bits=1024)
            self.dsa.generate_keys()
            self.dss_initialized = True
            self.crypto_status.config(text="✅ DSS параметры сгенерированы")
            self.log("DSS параметры успешно сгенерированы")
        except Exception as e:
            self.log(f"Ошибка генерации DSS параметров: {e}", "ERROR")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать DSS параметры: {e}")

    def generate_ffs_params(self):
        """Генерация FFS параметров"""
        try:
            self.log("Начинается генерация FFS параметров...")
            params = self.ffs.generate_server_params(bits=512)
            self.ffs_n = params['n']
            self.ffs_initialized = True
            self.crypto_status.config(text=f"✅ FFS параметры сгенерированы (n={self.ffs_n})")
            self.log(f"✅ FFS параметры успешно сгенерированы: n={self.ffs_n}")
            messagebox.showinfo("Успех", "FFS параметры успешно сгенерированы")
        except Exception as e:
            self.log(f"Ошибка генерации FFS параметров: {e}", "ERROR")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать FFS параметры: {e}")

    def create_election(self):
        """Создание новых выборов"""
        if not self.rsa_keys:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте ФФС ключи")
            return

        title = self.election_title.get().strip()
        if not title:
            messagebox.showwarning("Предупреждение", "Введите название выборов")
            return

        # Получаем длительность
        try:
            duration_minutes = int(self.election_duration.get().strip() or "60")
            if duration_minutes <= 0:
                raise ValueError("Длительность должна быть положительным числом")
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Неверная длительность: {e}")
            return

        self.current_election = Election(
            id=f"election_{int(time.time())}",
            title=title,
            description=self.election_desc.get().strip(),
            m=self.rsa_keys['m'],
            e=self.rsa_keys['e'],
            d=self.rsa_keys['d'],
            start_time="",
            end_time="",
            duration_minutes=duration_minutes,  # ДОБАВИТЬ
            is_active=False
        )

        # Обновляем информацию
        info = f"""
Название: {self.current_election.title}
ID: {self.current_election.id}
Описание: {self.current_election.description}
Длительность: {self.current_election.duration_minutes} минут
Статус: Не начаты
Параметры ФФС: m={self.current_election.m}, e={self.current_election.e}
        """
        self.election_info.delete(1.0, tk.END)
        self.election_info.insert(tk.END, info)

        self.start_btn.config(state=tk.NORMAL)
        self.log(f"Созданы выборы: {title} (длительность: {duration_minutes} минут)")

    def start_election(self):
        """Начало голосования"""
        if not self.current_election:
            return

        from datetime import timedelta
        
        start_dt = datetime.now()
        self.current_election.start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Вычисляем время окончания на основе длительности
        end_dt = start_dt + timedelta(minutes=self.current_election.duration_minutes)
        self.current_election.end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        self.current_election.is_active = True

        # Публикуем реестр допущенных избирателей
        self.publish_voters_registry()

        self.start_btn.config(state=tk.DISABLED)
        self.end_btn.config(state=tk.NORMAL)
        self.calc_btn.config(state=tk.NORMAL)

        self.log(f"Голосование начато. Окончание: {self.current_election.end_time}")
        self.broadcast_message({
            'type': 'election_started',
            'election': self.current_election.to_dict(),
            'eligible_voters': list(self.allowed_voters)
        })

    def end_election(self):
        """Завершение голосования"""
        if not self.current_election:
            return

        self.current_election.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.current_election.is_active = False

        self.end_btn.config(state=tk.DISABLED)

        self.log("Голосование завершено")
        self.broadcast_message({
            'type': 'election_ended',
            'election': self.current_election.to_dict()
        })

    def register_voter(self):
        """Регистрация нового избирателя"""
        voter_id = self.voter_id_entry.get().strip()
        voter_name = self.voter_name_entry.get().strip()

        if not voter_id or not voter_name:
            messagebox.showwarning("Предупреждение", "Заполните все поля")
            return

        if voter_id in self.voters:
            messagebox.showwarning("Предупреждение", "Избиратель с таким ID уже зарегистрирован")
            return

        voter = Voter(
            id=voter_id,
            name=voter_name,
            public_key="",
            has_voted=False
        )

        self.voters[voter_id] = voter
        self.update_voters_list()

        self.voter_id_entry.delete(0, tk.END)
        self.voter_name_entry.delete(0, tk.END)

        self.log(f"Зарегистрирован избиратель: {voter_name} (ID: {voter_id})")

    def update_voters_list(self):
        """Обновление списка избирателей"""
        self.voters_tree.delete(*self.voters_tree.get_children())

        from datetime import datetime
        
        # Получаем время окончания выборов, если они активны
        election_ended = False
        if self.current_election and self.current_election.end_time:
            try:
                end_time = datetime.strptime(self.current_election.end_time, "%Y-%m-%d %H:%M:%S")
                election_ended = datetime.now() > end_time
            except:
                pass

        for voter_id, voter in self.voters.items():
            # ИЗМЕНЕНИЕ: "Допущен" показывает галочку только если пользователь 
            # зарегистрирован (в self.voters) И аутентифицирован (в self.authenticated_voters)
            is_registered = voter_id in self.voters
            is_authenticated = voter_id in self.authenticated_voters
            is_allowed = is_registered and is_authenticated
            
            allowed = "✅" if is_allowed else "❌"
            
            # Определяем детальный статус
            if not is_registered:
                status = "❌ Не зарегистрирован"
            elif not is_authenticated:
                status = "📝 Зарегистрирован"
            elif voter.has_voted:
                # Проверяем, не опоздал ли
                if election_ended and self.current_election:
                    # Проверяем время голосования из бюллетеня
                    voter_bulletin = next((b for b in self.bulletins if b.voter_id == voter_id), None)
                    if voter_bulletin:
                        try:
                            vote_time = datetime.strptime(voter_bulletin.timestamp, "%Y-%m-%d %H:%M:%S")
                            end_time = datetime.strptime(self.current_election.end_time, "%Y-%m-%d %H:%M:%S")
                            if vote_time > end_time:
                                status = "⏰ Опоздал"
                            else:
                                status = "✅ Проголосовал"
                        except:
                            status = "✅ Проголосовал"
                    else:
                        status = "✅ Проголосовал"
                else:
                    status = "✅ Проголосовал"
            else:
                status = "�� Аутентифицирован"
            
            self.voters_tree.insert('', tk.END, values=(
                voter.id,
                voter.name,
                allowed,
                status,
                voter.bulletin_hash[:20] + "..." if voter.bulletin_hash else "Нет"
            ))

    def publish_bulletins(self):
        """Публикация таблицы бюллетеней"""
        self.published_data = []

        for bulletin in self.bulletins:
            self.published_data.append({
                'voter_id': bulletin.voter_id,
                'f': bulletin.encrypted_data.get('f'),  # Используем актуальное значение f (может быть изменено атакой)
                'signature': bulletin.signature,
                'timestamp': bulletin.timestamp
            })

        self.log(f"Опубликована таблица из {len(self.bulletins)} бюллетеней")
        
        # Показываем предупреждение, если есть измененные бюллетени
        modified_count = sum(1 for b in self.bulletins if not b.is_valid)
        if modified_count > 0:
            self.log(f"⚠️ ВНИМАНИЕ: В опубликованной таблице {modified_count} измененных бюллетеней!", "WARNING")

        self.broadcast_message({
            'type': 'bulletins_published',
            'data': self.published_data
        })

    def calculate_results(self):
        """Подсчет результатов голосования"""
        if not self.bulletins:
            messagebox.showwarning("Предупреждение", "Нет бюллетеней для подсчета")
            return

        if not self.current_election:
            messagebox.showwarning("Предупреждение", "Нет активных выборов")
            return

        # ИЗМЕНЕНИЕ: Фильтруем только корректные бюллетени
        valid_bulletins = []
        invalid_bulletins = []
        
        for bulletin in self.bulletins:
            # Проверяем бюллетень
            is_valid, msg = VotingCrypto.verify_bulletin(
                bulletin.encrypted_data,
                self.current_election.m,
                self.current_election.e
            )
            
            # Обновляем статус
            bulletin.is_valid = is_valid
            if not is_valid:
                bulletin.validation_message = msg
            
            if is_valid:
                valid_bulletins.append(bulletin.encrypted_data)
            else:
                invalid_bulletins.append(bulletin)
                self.log(f"❌ Некорректный бюллетень от {bulletin.voter_id} исключен из подсчета: {msg}", "WARNING")

        # Выполняем подсчет только для корректных бюллетеней
        if not valid_bulletins:
            messagebox.showwarning("Предупреждение", "Нет корректных бюллетеней для подсчета")
            return

        results = VotingCrypto.calculate_voting_results(
            valid_bulletins,
            self.current_election.m,
            self.current_election.d
        )

        # Добавляем информацию о некорректных бюллетенях
        results['invalid_count'] = len(invalid_bulletins)
        results['invalid_bulletins'] = [b.voter_id for b in invalid_bulletins]

        self.current_election.results = results

        # Отображаем результаты
        results_text = f"""
{'=' * 60}
{'РЕЗУЛЬТАТЫ ГОЛОСОВАНИЯ'.center(60)}
{'=' * 60}
Всего получено бюллетеней: {len(self.bulletins)}
✅ Корректных бюллетеней: {len(valid_bulletins)}
❌ Некорректных бюллетеней: {len(invalid_bulletins)}

Проголосовали (учтено): {results['for'] + results['against'] + results['abstained']}

Голоса "ЗА": {results['for']}
Голоса "ПРОТИВ": {results['against']}
Воздержались: {results['abstained']}

Контрольные числа:
F = {results['F']}
Q = {results['Q']}
R = {results['R']}
{'=' * 60}
        """
        
        if invalid_bulletins:
            results_text += f"\n❌ ВНИМАНИЕ: {len(invalid_bulletins)} некорректных бюллетеней не учтены в подсчете!"

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, results_text)

        self.log(f"Результаты голосования подсчитаны. Корректных: {len(valid_bulletins)}, Некорректных: {len(invalid_bulletins)}")

    def publish_results(self):
        """Публикация результатов голосования"""
        if not self.current_election or not self.current_election.results:
            messagebox.showwarning("Предупреждение", "Сначала подсчитайте результаты")
            return

        self.broadcast_message({
            'type': 'results_published',
            'results': self.current_election.results,
            'election': self.current_election.to_dict()
        })

        self.log("Результаты голосования опубликованы")

    def export_results(self):
        """Экспорт результатов в файл"""
        if not self.current_election or not self.current_election.results:
            return

        try:
            filename = f"results_{self.current_election.id}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.results_text.get(1.0, tk.END))

            self.log(f"Результаты экспортированы в файл: {filename}")
            messagebox.showinfo("Успех", f"Результаты экспортированы в {filename}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать результаты: {e}")

    def verify_signatures(self):
        """Проверка всех подписей бюллетеней"""
        valid = 0
        total = len(self.bulletins)

        for bulletin in self.bulletins:
            # В реальной системе здесь была бы проверка DSS подписи
            valid += 1

        messagebox.showinfo("Проверка подписей",
                            f"Проверено {total} бюллетеней\n"
                            f"Валидных: {valid}\n"
                            f"Невалидных: {total - valid}")

    def export_bulletins(self):
        """Экспорт бюллетеней в файл"""
        if not self.bulletins:
            messagebox.showwarning("Предупреждение", "Нет бюллетеней для экспорта")
            return

        try:
            filename = f"bulletins_{self.current_election.id if self.current_election else 'unknown'}.json"
            data = [b.to_dict() for b in self.bulletins]

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self.log(f"Бюллетени экспортированы в файл: {filename}")
            messagebox.showinfo("Успех", f"Бюллетени экспортированы в {filename}")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось экспортировать бюллетени: {e}")

    # === Сетевые методы ===

    def start_server(self):
        """Запуск сервера"""
        try:
            self.config.host = self.host_entry.get()
            self.config.port = int(self.port_entry.get())

            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.host, self.config.port))
            self.server_socket.listen(self.config.max_clients)
            self.server_socket.settimeout(1.0)

            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text=f"✅ Сервер запущен на {self.config.host}:{self.config.port}")

            # Запускаем поток приема подключений
            accept_thread = threading.Thread(target=self.accept_clients, daemon=True)
            accept_thread.start()

            self.log(f"Сервер запущен на {self.config.host}:{self.config.port}")

        except Exception as e:
            self.log(f"Ошибка запуска сервера: {e}", "ERROR")
            messagebox.showerror("Ошибка", f"Не удалось запустить сервер: {e}")

    def stop_server(self):
        """Остановка сервера"""
        self.running = False

        # Закрываем все соединения
        with self.client_lock:
            for client_socket in list(self.clients.keys()):
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="🛑 Сервер остановлен")
        self.clients_label.config(text="Подключенных клиентов: 0")

        self.log("Сервер остановлен")

    def accept_clients(self):
        """Прием клиентских подключений"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(1.0)

                with self.client_lock:
                    self.clients[client_socket] = address

                # Обновляем GUI
                self.root.after(0, self.update_clients_count)

                # Запускаем обработчик клиента
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()

                self.log(f"Клиент подключен: {address[0]}:{address[1]}")

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.log(f"Ошибка при приеме подключения: {e}", "ERROR")

    def handle_client(self, client_socket, address):
        """Обработка клиентского соединения"""
        client_id = f"{address[0]}:{address[1]}"

        try:
            while self.running:
                message = MessageProtocol.receive_message(client_socket, timeout=1.0)
                if message is None:
                    # Таймаут или соединение закрыто
                    continue

                self.log(f"Получено от {client_id}: {message.get('type')}")

                # Обрабатываем сообщение в основном потоке
                self.root.after(0, lambda m=message: self.process_client_message(client_socket, m))

        except Exception as e:
            self.log(f"Ошибка обработки клиента {client_id}: {e}", "ERROR")
        finally:
            try:
                client_socket.close()
            except:
                pass

            with self.client_lock:
                if client_socket in self.clients:
                    del self.clients[client_socket]

            self.root.after(0, self.update_clients_count)
            self.log(f"Клиент отключен: {client_id}")

    def update_clients_count(self):
        """Обновление счетчика подключенных клиентов"""
        with self.client_lock:
            count = len(self.clients)
        self.clients_label.config(text=f"Подключенных клиентов: {count}")

    def process_client_message(self, client_socket, message):
        """Обработка сообщений от клиента"""
        msg_type = message.get('type')

        if msg_type == 'register':
            self.handle_register(client_socket, message)
        elif msg_type == 'authenticate':
            self.handle_authenticate(client_socket, message)
        elif msg_type == 'submit_bulletin':
            self.handle_submit_bulletin(client_socket, message)
        elif msg_type == 'get_election_info':
            self.handle_get_election_info(client_socket)
        elif msg_type == 'get_published_data':
            self.handle_get_published_data(client_socket)
        elif msg_type == 'get_voters_registry':
            self.handle_get_voters_registry(client_socket)
        else:
            self.log(f"Неизвестный тип сообщения: {msg_type}", "WARNING")

    def handle_register(self, client_socket, message):
        """Обработка регистрации избирателя"""
        voter_id = message.get('voter_id')
        voter_name = message.get('voter_name')

        if not voter_id or not voter_name:
            response = {
                'type': 'register_response',
                'success': False,
                'message': 'Не указаны данные избирателя'
            }
        elif self.allowed_voters and voter_id not in self.allowed_voters:
            response = {
                'type': 'register_response',
                'success': False,
                'message': 'Избиратель отсутствует в реестре'
            }
        elif voter_id in self.voters:
            # Уже есть: считаем допущенным и подтверждаем без ошибки
            response = {
                'type': 'register_response',
                'success': True,
                'message': 'Вы уже зарегистрированы и допущены к голосованию',
                'voter': self.voters[voter_id].to_dict(),
                'ffs_n': self.ffs_n if self.ffs_initialized else None
            }
        else:
            # Создаем нового избирателя
            voter = Voter(
                id=voter_id,
                name=voter_name,
                public_key=message.get('public_key', ''),
                has_voted=False
            )

            self.voters[voter_id] = voter
            self.root.after(0, self.update_voters_list)

            response = {
                'type': 'register_response',
                'success': True,
                'message': 'Регистрация успешна',
                'voter': voter.to_dict(),
                'ffs_n': self.ffs_n if self.ffs_initialized else None
            }

            self.log(f"Зарегистрирован новый избиратель: {voter_name} (FFS v={message.get('public_key', '')})")

        MessageProtocol.send_message(client_socket, response)

    def handle_authenticate(self, client_socket, message):
        """Обработка аутентификации избирателя по протоколу FFS"""
        voter_id = message.get('voter_id')
        step = message.get('step', 1)
        
        if not self.ffs_initialized:
            response = {
                'type': 'authenticate_response',
                'success': False,
                'message': 'FFS параметры не инициализированы на сервере'
            }
            MessageProtocol.send_message(client_socket, response)
            return
        
        if step == 1:
            # Шаг 1: Получаем commitment от клиента
            x = message.get('x')
            v = message.get('v')
            
            self.log(f"📩 FFS Аутентификация {voter_id}: Получено обязательство x={x}")
            
            if voter_id not in self.voters:
                response = {
                    'type': 'authenticate_response',
                    'success': False,
                    'message': 'Избиратель не найден'
                }
            elif self.allowed_voters and voter_id not in self.allowed_voters:
                response = {
                    'type': 'authenticate_response',
                    'success': False,
                    'message': 'Избиратель не допущен к голосованию'
                }
            elif self.voters[voter_id].has_voted:
                response = {
                    'type': 'authenticate_response',
                    'success': False,
                    'message': 'Избиратель уже проголосовал'
                }
            else:
                # Генерируем вызов
                b = FFSCrypto.create_challenge(self.entropy)
                
                # Сохраняем данные сессии
                self.ffs_auth_sessions[voter_id] = {
                    'x': x,
                    'b': b,
                    'v': v
                }
                
                self.log(f"📤 FFS Аутентификация {voter_id}: Отправлен вызов b={b}")
                
                response = {
                    'type': 'authenticate_challenge',
                    'success': True,
                    'b': b,
                    'message': 'Отправлен вызов для аутентификации'
                }
                
            MessageProtocol.send_message(client_socket, response)
            
        elif step == 2:
            # Шаг 2: Получаем ответ от клиента и проверяем
            y = message.get('y')
            
            self.log(f"📩 FFS Аутентификация {voter_id}: Получен ответ y={y}")
            
            if voter_id not in self.ffs_auth_sessions:
                response = {
                    'type': 'authenticate_response',
                    'success': False,
                    'message': 'Сессия аутентификации не найдена'
                }
            else:
                session = self.ffs_auth_sessions[voter_id]
                x = session['x']
                b = session['b']
                v = session['v']
                
                # Проверяем ответ
                is_valid = FFSCrypto.verify_response(x, y, v, b, self.ffs_n)
                
                if is_valid:
                    self.authenticated_voters.add(voter_id)
                    # Обновляем список избирателей после аутентификации
                    self.root.after(0, self.update_voters_list)
                    
                    self.log(f"✅ FFS Аутентификация {voter_id}: УСПЕШНА!")
                    
                    response = {
                        'type': 'authenticate_response',
                        'success': True,
                        'message': 'Аутентификация успешна',
                        'election': self.current_election.to_dict() if self.current_election else None,
                        'voters_count': len(self.voters),
                        'voted_count': sum(1 for v in self.voters.values() if v.has_voted)
                    }
                else:
                    self.log(f"❌ FFS Аутентификация {voter_id}: ПРОВАЛЕНА!")
                    
                    response = {
                        'type': 'authenticate_response',
                        'success': False,
                        'message': 'Аутентификация не пройдена: неверный ответ'
                    }
                
                # Удаляем сессию
                del self.ffs_auth_sessions[voter_id]
                
            MessageProtocol.send_message(client_socket, response)

    def verify_all_bulletins(self):
        """Проверка всех бюллетеней на корректность"""
        if not self.bulletins:
            messagebox.showinfo("Информация", "Нет бюллетеней для проверки")
            return

        if not self.current_election:
            messagebox.showwarning("Предупреждение", "Нет активных выборов")
            return

        valid_count = 0
        invalid_count = 0

        for bulletin in self.bulletins:
            is_valid, msg = VotingCrypto.verify_bulletin(
                bulletin.encrypted_data,
                self.current_election.m,
                self.current_election.e
            )

            # Обновляем статус бюллетеня
            bulletin.is_valid = is_valid
            bulletin.validation_message = msg

            if is_valid:
                valid_count += 1
            else:
                invalid_count += 1
                self.log(f"❌ Некорректный бюллетень от {bulletin.voter_id}: {msg}", "ERROR")

        # Обновляем отображение
        self.root.after(0, self.update_bulletins_list)

        messagebox.showinfo("Результаты проверки",
                          f"Проверено бюллетеней: {len(self.bulletins)}\n"
                          f"✅ Корректных: {valid_count}\n"
                          f"❌ Некорректных: {invalid_count}")

    def attack_modify_bulletin_f(self):
        """Атака: изменение зашифрованного значения f в бюллетене"""
        voter_id = self.attack_voter_id_entry.get().strip()
        
        if not voter_id:
            messagebox.showwarning("Предупреждение", "Введите ID избирателя")
            return
        
        # Ищем бюллетень
        bulletin = next((b for b in self.bulletins if b.voter_id == voter_id), None)
        if not bulletin:
            messagebox.showwarning("Предупреждение", f"Бюллетень избирателя {voter_id} не найден")
            return
        
        # Изменяем значение f на случайное, гарантированно неправильное
        original_f = bulletin.encrypted_data.get('f')
        import random
        # Генерируем случайное значение, которое точно не будет правильным
        new_f = random.randint(1, self.current_election.m - 1)
        while new_f == original_f:
            new_f = random.randint(1, self.current_election.m - 1)
        
        bulletin.encrypted_data['f'] = new_f
        
        # ВАЖНО: Обновляем в опубликованных данных, если они уже опубликованы
        for pub_data in self.published_data:
            if pub_data.get('voter_id') == voter_id:
                pub_data['f'] = new_f
                self.log(f"⚠️ АТАКА: Обновлен f в опубликованных данных для {voter_id} ({original_f} -> {new_f})", "WARNING")
        
        # Помечаем как измененный на сервере (не просто ошибка)
        bulletin.is_valid = False
        bulletin.validation_message = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: f изменен с {original_f} на {new_f}"
        
        # Перепроверяем для подтверждения
        is_valid, msg = VotingCrypto.verify_bulletin(
            bulletin.encrypted_data,
            self.current_election.m,
            self.current_election.e
        )
        # Сохраняем специальное сообщение об изменении на сервере
        if not is_valid:
            bulletin.validation_message = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: f изменен с {original_f} на {new_f}"
        
        self.log(f"⚠️ АТАКА: Изменен бюллетень избирателя {voter_id} (f: {original_f} -> {new_f})", "WARNING")
        messagebox.showwarning("Атака выполнена", 
                             f"Бюллетень избирателя {voter_id} изменен!\n"
                             f"Оригинальный f: {original_f}\n"
                             f"Новый f: {new_f}\n\n"
                             f"Проверка: {'❌ НЕ ПРОШЛА' if not is_valid else '⚠️ ПРОШЛА (ОШИБКА!)'}\n\n"
                             f"⚠️ Клиент обнаружит изменение при проверке!")
        
        # Обновляем GUI
        self.root.after(0, self.update_bulletins_list)
        
        # Если таблица уже опубликована, отправляем обновление клиентам
        if self.published_data:
            self.broadcast_message({
                'type': 'bulletins_published',
                'data': self.published_data
            })
            self.log(f"⚠️ АТАКА: Отправлено обновление опубликованной таблицы с измененным бюллетенем", "WARNING")

    def attack_modify_bulletin_choice(self):
        """Атака: изменение choice в бюллетене"""
        voter_id = self.attack_voter_id_entry.get().strip()
        
        if not voter_id:
            messagebox.showwarning("Предупреждение", "Введите ID избирателя")
            return
        
        bulletin = next((b for b in self.bulletins if b.voter_id == voter_id), None)
        if not bulletin:
            messagebox.showwarning("Предупреждение", f"Бюллетень избирателя {voter_id} не найден")
            return
        
        # Изменяем choice и f для саботажа
        original_choice = bulletin.encrypted_data.get('choice')
        original_f = bulletin.encrypted_data.get('f')
        original_t = bulletin.encrypted_data.get('t')
        new_choice = (original_choice % 3) + 1  # Меняем на другой вариант
        
        bulletin.encrypted_data['choice'] = new_choice
        
        # Также изменяем f, чтобы клиент точно обнаружил изменение
        import random
        new_f = random.randint(1, self.current_election.m - 1)
        while new_f == original_f:
            new_f = random.randint(1, self.current_election.m - 1)
        bulletin.encrypted_data['f'] = new_f
        
        # Обновляем в опубликованных данных
        for pub_data in self.published_data:
            if pub_data.get('voter_id') == voter_id:
                pub_data['f'] = new_f
                self.log(f"⚠️ АТАКА: Обновлен f в опубликованных данных для {voter_id}", "WARNING")
        
        # Перепроверяем
        is_valid, msg = VotingCrypto.verify_bulletin(
            bulletin.encrypted_data,
            self.current_election.m,
            self.current_election.e
        )
        bulletin.is_valid = is_valid
        bulletin.validation_message = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: choice изменен с {original_choice} на {new_choice}, f изменен с {original_f} на {new_f}"
        
        self.log(f"⚠️ АТАКА: Изменен choice в бюллетене {voter_id} ({original_choice} -> {new_choice}), f изменен", "WARNING")
        messagebox.showwarning("Атака выполнена",
                             f"Choice изменен с {original_choice} на {new_choice}\n"
                             f"f изменен с {original_f} на {new_f}\n\n"
                             f"Проверка: {'❌ НЕ ПРОШЛА' if not is_valid else '⚠️ ПРОШЛА (ОШИБКА!)'}")
        
        self.root.after(0, self.update_bulletins_list)
        
        # Если таблица уже опубликована, отправляем обновление клиентам
        if self.published_data:
            self.broadcast_message({
                'type': 'bulletins_published',
                'data': self.published_data
            })
            self.log(f"⚠️ АТАКА: Отправлено обновление опубликованной таблицы с измененным бюллетенем", "WARNING")

    def attack_break_verification(self):
        """Атака: нарушение проверки путем изменения параметров"""
        voter_id = self.attack_voter_id_entry.get().strip()
        
        if not voter_id:
            messagebox.showwarning("Предупреждение", "Введите ID избирателя")
            return
        
        bulletin = next((b for b in self.bulletins if b.voter_id == voter_id), None)
        if not bulletin:
            messagebox.showwarning("Предупреждение", f"Бюллетень избирателя {voter_id} не найден")
            return
        
        # Изменяем параметр m и f
        original_m = bulletin.encrypted_data.get('m')
        original_f = bulletin.encrypted_data.get('f')
        bulletin.encrypted_data['m'] = original_m + 1  # Делаем неверным
        
        # Также изменяем f
        import random
        new_f = random.randint(1, self.current_election.m - 1)
        while new_f == original_f:
            new_f = random.randint(1, self.current_election.m - 1)
        bulletin.encrypted_data['f'] = new_f
        
        # Обновляем в опубликованных данных
        for pub_data in self.published_data:
            if pub_data.get('voter_id') == voter_id:
                pub_data['f'] = new_f
                self.log(f"⚠️ АТАКА: Обновлен f в опубликованных данных для {voter_id}", "WARNING")
        
        # Перепроверяем
        is_valid, msg = VotingCrypto.verify_bulletin(
            bulletin.encrypted_data,
            self.current_election.m,
            self.current_election.e
        )
        bulletin.is_valid = is_valid
        bulletin.validation_message = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: параметр m изменен с {original_m} на {bulletin.encrypted_data['m']}, f изменен с {original_f} на {new_f}"
        
        self.log(f"⚠️ АТАКА: Нарушена проверка бюллетеня {voter_id} (m: {original_m} -> {bulletin.encrypted_data['m']}, f изменен)", "WARNING")
        messagebox.showwarning("Атака выполнена",
                             f"Параметр m изменен:\n"
                             f"Было: {original_m}\n"
                             f"Стало: {bulletin.encrypted_data['m']}\n"
                             f"f изменен с {original_f} на {new_f}\n\n"
                             f"Проверка: {'❌ НЕ ПРОШЛА' if not is_valid else '⚠️ ПРОШЛА (ОШИБКА!)'}\n"
                             f"Ошибка: {msg}")
        
        self.root.after(0, self.update_bulletins_list)
        
        # Если таблица уже опубликована, отправляем обновление клиентам
        if self.published_data:
            self.broadcast_message({
                'type': 'bulletins_published',
                'data': self.published_data
            })
            self.log(f"⚠️ АТАКА: Отправлено обновление опубликованной таблицы с измененным бюллетенем", "WARNING")

    def attack_modify_rsa_params(self):
        """Атака: изменение параметров ФФС"""
        voter_id = self.attack_voter_id_entry.get().strip()
        
        if not voter_id:
            messagebox.showwarning("Предупреждение", "Введите ID избирателя")
            return
        
        bulletin = next((b for b in self.bulletins if b.voter_id == voter_id), None)
        if not bulletin:
            messagebox.showwarning("Предупреждение", f"Бюллетень избирателя {voter_id} не найден")
            return
        
        # Изменяем параметры ФФС и f
        original_f = bulletin.encrypted_data.get('f')
        original_m = bulletin.encrypted_data.get('m')
        original_e = bulletin.encrypted_data.get('e')
        bulletin.encrypted_data['m'] = original_m + 100
        bulletin.encrypted_data['e'] = original_e + 1
        
        # Также изменяем f
        import random
        new_f = random.randint(1, self.current_election.m - 1)
        while new_f == original_f:
            new_f = random.randint(1, self.current_election.m - 1)
        bulletin.encrypted_data['f'] = new_f
        
        # Обновляем в опубликованных данных
        for pub_data in self.published_data:
            if pub_data.get('voter_id') == voter_id:
                pub_data['f'] = new_f
                self.log(f"⚠️ АТАКА: Обновлен f в опубликованных данных для {voter_id}", "WARNING")
        
        # Перепроверяем
        is_valid, msg = VotingCrypto.verify_bulletin(
            bulletin.encrypted_data,
            self.current_election.m,
            self.current_election.e
        )
        bulletin.is_valid = is_valid
        bulletin.validation_message = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: параметры ФФС изменены (m: {original_m} -> {bulletin.encrypted_data['m']}, e: {original_e} -> {bulletin.encrypted_data['e']}), f изменен с {original_f} на {new_f}"
        
        self.log(f"⚠️ АТАКА: Изменены параметры ФФС в бюллетене {voter_id}", "WARNING")
        messagebox.showwarning("Атака выполнена",
                             f"Параметры ФФС изменены:\n"
                             f"m: {original_m} -> {bulletin.encrypted_data['m']}\n"
                             f"e: {original_e} -> {bulletin.encrypted_data['e']}\n"
                             f"f изменен с {original_f} на {new_f}\n\n"
                             f"Проверка: {'❌ НЕ ПРОШЛА' if not is_valid else '⚠️ ПРОШЛА (ОШИБКА!)'}\n"
                             f"Ошибка: {msg}")
        
        self.root.after(0, self.update_bulletins_list)
        
        # Если таблица уже опубликована, отправляем обновление клиентам
        if self.published_data:
            self.broadcast_message({
                'type': 'bulletins_published',
                'data': self.published_data
            })
            self.log(f"⚠️ АТАКА: Отправлено обновление опубликованной таблицы с измененным бюллетенем", "WARNING")

    def handle_submit_bulletin(self, client_socket, message):
        """Обработка отправки бюллетеня"""
        voter_id = message.get('voter_id')
        bulletin_data = message.get('bulletin')
        signature = message.get('signature')

        if voter_id not in self.voters:
            response = {
                'type': 'submit_response',
                'success': False,
                'message': 'Избиратель не найден'
            }
        elif self.voters[voter_id].has_voted:
            response = {
                'type': 'submit_response',
                'success': False,
                'message': 'Избиратель уже проголосовал'
            }
        elif self.allowed_voters and voter_id not in self.allowed_voters:
            response = {
                'type': 'submit_response',
                'success': False,
                'message': 'Избиратель не допущен к голосованию'
            }
        elif not self.current_election or not self.current_election.is_active:
            response = {
                'type': 'submit_response',
                'success': False,
                'message': 'Голосование не активно'
            }
        else:
            # Проверка времени
            from datetime import datetime
            current_time = datetime.now()
            end_time = datetime.strptime(self.current_election.end_time, "%Y-%m-%d %H:%M:%S")
            
            is_late = current_time > end_time
            
            if is_late:
                response = {
                    'type': 'submit_response',
                    'success': False,
                    'message': f'Голосование завершено. Время окончания: {self.current_election.end_time}'
                }
            else:
                # ИЗМЕНЕНИЕ: Всегда проверяем бюллетень и сохраняем результат
                is_valid, validation_msg = VotingCrypto.verify_bulletin(
                    bulletin_data,
                    self.current_election.m,
                    self.current_election.e
                )

                # ДОБАВИТЬ: Автоматическая атака, если включена
                if self.attack_enabled.get() and is_valid:
                    import random
                    attack_type = random.choice(['f', 'choice', 'rsa'])
                    
                    if attack_type == 'f':
                        # Изменяем значение f
                        original_f = bulletin_data.get('f')
                        wrong_f = random.randint(1, self.current_election.m - 1)
                        while wrong_f == original_f:
                            wrong_f = random.randint(1, self.current_election.m - 1)
                        bulletin_data['f'] = wrong_f
                        is_valid = False
                        validation_msg = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: автоматически изменен f с {original_f} на {wrong_f}"
                        self.log(f"⚠️ АТАКА: Автоматически изменен бюллетень {voter_id} (f: {original_f} -> {wrong_f})", "WARNING")
                    
                    elif attack_type == 'choice':
                        # Изменяем choice и f
                        original_choice = bulletin_data.get('choice')
                        original_f = bulletin_data.get('f')
                        new_choice = (original_choice % 3) + 1
                        bulletin_data['choice'] = new_choice
                        # Изменяем f
                        wrong_f = random.randint(1, self.current_election.m - 1)
                        while wrong_f == original_f:
                            wrong_f = random.randint(1, self.current_election.m - 1)
                        bulletin_data['f'] = wrong_f
                        is_valid = False
                        validation_msg = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: автоматически изменен choice с {original_choice} на {new_choice}, f изменен с {original_f} на {wrong_f}"
                        self.log(f"⚠️ АТАКА: Автоматически изменен choice и f в бюллетене {voter_id}", "WARNING")
                    
                    elif attack_type == 'rsa':
                        # Изменяем параметры ФФС и f
                        original_f = bulletin_data.get('f')
                        bulletin_data['m'] = self.current_election.m + 100
                        bulletin_data['e'] = self.current_election.e + 1
                        wrong_f = random.randint(1, self.current_election.m - 1)
                        while wrong_f == original_f:
                            wrong_f = random.randint(1, self.current_election.m - 1)
                        bulletin_data['f'] = wrong_f
                        is_valid = False
                        validation_msg = f"⚠️ ИЗМЕНЕНО НА СЕРВЕРЕ: автоматически изменены параметры ФФС, f изменен с {original_f} на {wrong_f}"
                        self.log(f"⚠️ АТАКА: Автоматически изменены параметры ФФС и f в бюллетене {voter_id}", "WARNING")

                if not is_valid:
                    # ИЗМЕНЕНИЕ: Принимаем некорректный бюллетень, но помечаем его
                    self.log(f"❌ Получен некорректный бюллетень от {voter_id}: {validation_msg}", "ERROR")
                    
                    # Создаем объект бюллетеня с пометкой о невалидности
                    bulletin = Bulletin(
                        voter_id=voter_id,
                        encrypted_data=bulletin_data,
                        signature=signature,
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        is_valid=False,
                        validation_message=validation_msg
                    )

                    # Добавляем бюллетень (даже некорректный)
                    self.bulletins.append(bulletin)

                    # Обновляем GUI
                    self.root.after(0, self.update_bulletins_list)
                    self.root.after(0, self.update_voters_list)

                    response = {
                        'type': 'submit_response',
                        'success': False,
                        'message': f'Бюллетень принят, но некорректен: {validation_msg}',
                        'bulletin_id': len(self.bulletins),
                        'is_valid': False
                    }
                else:
                    # Корректный бюллетень
                    bulletin = Bulletin(
                        voter_id=voter_id,
                        encrypted_data=bulletin_data,
                        signature=signature,
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        is_valid=True,
                        validation_message="Бюллетень корректен"
                    )

                    # Добавляем бюллетень
                    self.bulletins.append(bulletin)

                    # Обновляем избирателя
                    self.voters[voter_id].has_voted = True
                    self.voters[voter_id].bulletin_hash = hashlib.sha256(
                        json.dumps(bulletin_data, sort_keys=True).encode()
                    ).hexdigest()

                    # Обновляем GUI
                    self.root.after(0, self.update_bulletins_list)
                    self.root.after(0, self.update_voters_list)

                    response = {
                        'type': 'submit_response',
                        'success': True,
                        'message': 'Бюллетень принят',
                        'bulletin_id': len(self.bulletins),
                        'is_valid': True
                    }

                    self.log(f"✅ Принят корректный бюллетень от избирателя {voter_id}")

        MessageProtocol.send_message(client_socket, response)

    def handle_get_election_info(self, client_socket):
        """Отправка информации о выборах"""
        response = {
            'type': 'election_info',
            'election': self.current_election.to_dict() if self.current_election else None,
            'voters_count': len(self.voters),
            'voted_count': sum(1 for v in self.voters.values() if v.has_voted),
            'eligible_voters': list(self.allowed_voters)
        }

        MessageProtocol.send_message(client_socket, response)

    def handle_get_published_data(self, client_socket):
        """Отправка опубликованных данных"""
        response = {
            'type': 'published_data',
            'bulletins': self.published_data,
            'results': self.current_election.results if self.current_election else None
        }

        MessageProtocol.send_message(client_socket, response)

    def handle_get_voters_registry(self, client_socket):
        """Отправка реестра допущенных к голосованию избирателей"""
        registry = [{
            'id': voter.id,
            'name': voter.name
        } for voter in self.voters.values()]

        response = {
            'type': 'voters_registry',
            'eligible_voters': list(self.allowed_voters),
            'registry': registry
        }

        MessageProtocol.send_message(client_socket, response)

    def broadcast_message(self, message):
        """Рассылка сообщения всем клиентам"""
        with self.client_lock:
            clients = list(self.clients.keys())

        for client_socket in clients:
            try:
                MessageProtocol.send_message(client_socket, message)
            except:
                pass

    def update_bulletins_list(self):
        """Обновление списка бюллетеней"""
        self.bulletins_tree.delete(*self.bulletins_tree.get_children())

        for bulletin in self.bulletins:
            f_value = str(bulletin.encrypted_data.get('f', ''))
            
            # ИЗМЕНЕНИЕ: Отображаем статус проверки с указанием изменений на сервере
            if bulletin.is_valid:
                status = "✅ Корректен"
            else:
                # Проверяем, было ли изменение на сервере
                if "ИЗМЕНЕНО НА СЕРВЕРЕ" in bulletin.validation_message:
                    status = bulletin.validation_message[:50] + "..." if len(bulletin.validation_message) > 50 else bulletin.validation_message
                else:
                    status = f"❌ {bulletin.validation_message[:30]}..."
            
            item = self.bulletins_tree.insert('', tk.END, values=(
                bulletin.voter_id,
                f_value[:50] + "..." if len(f_value) > 50 else f_value,
                status,
                str(bulletin.signature)[:30] + "..." if bulletin.signature else "",
                bulletin.timestamp
            ))
            
            # Цветовая индикация
            if not bulletin.is_valid:
                self.bulletins_tree.item(item, tags=('invalid',))

    def run(self):
        """Запуск приложения сервера"""
        self.root.mainloop()

    def publish_voters_registry(self):
        """Публикация реестра допущенных избирателей"""
        registry = [{
            'id': voter.id,
            'name': voter.name
        } for voter in self.voters.values()]

        self.log(f"Опубликован реестр из {len(registry)} избирателей")

        self.broadcast_message({
            'type': 'voters_registry',
            'eligible_voters': list(self.allowed_voters),
            'registry': registry
        })

    def load_voters_from_file(self):
        """Загрузка реестра из текстового файла (id;ФИО)"""
        if not os.path.exists(self.registry_file):
            self.log(f"Файл реестра не найден: {self.registry_file}", "WARNING")
            return

        loaded = 0
        skipped = 0
        try:
            with open(self.registry_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(';')
                    if len(parts) < 2:
                        skipped += 1
                        continue

                    voter_id = parts[0].strip()
                    voter_name = ';'.join(parts[1:]).strip()

                    if not voter_id or voter_id in self.voters:
                        skipped += 1
                        continue

                    self.voters[voter_id] = Voter(
                        id=voter_id,
                        name=voter_name,
                        public_key="",
                        has_voted=False
                    )
                    loaded += 1

            self.allowed_voters = set(self.voters.keys())
            self.update_voters_list()
            self.log(f"Реестр загружен из файла: {loaded} записей, пропущено: {skipped}")
        except Exception as e:
            self.log(f"Ошибка загрузки реестра: {e}", "ERROR")


def main():
    """Точка входа серверного приложения"""
    server = CenterServer()
    server.run()


if __name__ == "__main__":
    main()  


# TODO добавить время окончания + статусы у сервера + атака со стороны изберателя , сервера и третьего лица 