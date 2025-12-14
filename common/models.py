"""
Модели данных для электронного голосования
"""
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional
import json
from datetime import datetime


@dataclass
class Voter:
    """Модель избирателя"""
    id: str
    name: str
    public_key: str = ""
    has_voted: bool = False
    bulletin_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Voter':
        return cls(**data)


@dataclass
class Bulletin:
    """Модель бюллетеня"""
    voter_id: str
    encrypted_data: Dict[str, Any]
    signature: Dict[str, Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Bulletin':
        return cls(**data)


@dataclass
class Election:
    """Модель выборов"""
    id: str
    title: str
    description: str
    m: int  # Модуль RSA
    e: int  # Открытая экспонента RSA
    d: int  # Закрытая экспонента RSA (только у Центра)
    start_time: str
    end_time: str
    duration_minutes: int = 60  # Длительность голосования в минутах (по умолчанию 60)
    is_active: bool = False
    results: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        # Не передаем закрытый ключ клиентам
        data['d'] = None
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Election':
        return cls(**data)


@dataclass
class ServerConfig:
    """Конфигурация сервера"""
    host: str = "127.0.0.1"
    port: int = 8888
    max_clients: int = 100