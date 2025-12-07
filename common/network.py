import socket
import json
import threading
from typing import Dict, Any, Callable


class NetworkProtocol:
    """Протокол сетевого обмена для электронного голосования"""

    @staticmethod
    def create_message(msg_type: str, **kwargs) -> Dict[str, Any]:
        """Создание структурированного сообщения"""
        message = {
            'type': msg_type,
            'timestamp': kwargs.get('timestamp'),
            'data': kwargs
        }
        message.update(kwargs)
        return message

    @staticmethod
    def send_message(sock: socket.socket, message: Dict[str, Any]) -> bool:
        """Отправка сообщения через сокет"""
        try:
            data = json.dumps(message, default=str).encode('utf-8')
            sock.send(len(data).to_bytes(4, 'big'))
            sock.send(data)
            return True
        except Exception as e:
            print(f"Ошибка отправки сообщения: {e}")
            return False

    @staticmethod
    def receive_message(sock: socket.socket) -> Dict[str, Any]:
        """Получение сообщения из сокета"""
        try:
            # Получаем длину сообщения
            length_bytes = sock.recv(4)
            if not length_bytes:
                return {}

            length = int.from_bytes(length_bytes, 'big')

            # Получаем само сообщение
            chunks = []
            bytes_received = 0

            while bytes_received < length:
                chunk = sock.recv(min(length - bytes_received, 4096))
                if not chunk:
                    return {}
                chunks.append(chunk)
                bytes_received += len(chunk)

            data = b''.join(chunks)
            return json.loads(data.decode('utf-8'))

        except Exception as e:
            print(f"Ошибка получения сообщения: {e}")
            return {}


class MessageHandler:
    """Обработчик сообщений"""

    def __init__(self):
        self.handlers = {}

    def register_handler(self, message_type: str, handler: Callable):
        """Регистрация обработчика для типа сообщения"""
        self.handlers[message_type] = handler

    def handle_message(self, message: Dict[str, Any], **kwargs):
        """Обработка сообщения"""
        msg_type = message.get('type')
        if msg_type in self.handlers:
            return self.handlers[msg_type](message, **kwargs)
        return None