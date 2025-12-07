"""
Сетевой протокол для электронного голосования
"""
import socket
import json
import struct
from typing import Dict, Any, Optional


class MessageProtocol:
    """Протокол обмена сообщениями"""

    HEADER_FORMAT = '!I'  # 4-байтовый беззнаковый int (длина сообщения)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    @staticmethod
    def send_message(sock: socket.socket, message: Dict[str, Any]) -> bool:
        """Отправка сообщения через сокет"""
        try:
            # Сериализуем сообщение в JSON
            data = json.dumps(message, ensure_ascii=False).encode('utf-8')

            # Упаковываем длину сообщения
            header = struct.pack(MessageProtocol.HEADER_FORMAT, len(data))

            # Отправляем заголовок и данные
            sock.sendall(header)
            sock.sendall(data)

            return True
        except Exception as e:
            print(f"Ошибка отправки сообщения: {e}")
            return False

    @staticmethod
    def receive_message(sock: socket.socket, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Получение сообщения из сокета"""
        original_timeout = sock.gettimeout()
        try:
            if timeout is not None:
                sock.settimeout(timeout)

            # Получаем заголовок
            header_data = b""
            while len(header_data) < MessageProtocol.HEADER_SIZE:
                chunk = sock.recv(MessageProtocol.HEADER_SIZE - len(header_data))
                if not chunk:
                    return None
                header_data += chunk

            # Распаковываем длину сообщения
            message_length = struct.unpack(MessageProtocol.HEADER_FORMAT, header_data)[0]

            # Получаем данные сообщения
            message_data = b""
            while len(message_data) < message_length:
                chunk = sock.recv(min(4096, message_length - len(message_data)))
                if not chunk:
                    return None
                message_data += chunk

            # Десериализуем JSON
            return json.loads(message_data.decode('utf-8'))

        except socket.timeout:
            return None
        except Exception as e:
            print(f"Ошибка получения сообщения: {e}")
            return None
        finally:
            sock.settimeout(original_timeout)