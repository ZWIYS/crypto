import socket
import json


def test_connection():
    """Простой тест подключения к серверу"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', 8888))

        print("✅ Подключение успешно")

        # Тестовое сообщение
        test_msg = {'type': 'test', 'message': 'Hello server'}
        data = json.dumps(test_msg).encode('utf-8')

        # Отправляем длину
        sock.sendall(len(data).to_bytes(4, 'big'))
        # Отправляем данные
        sock.sendall(data)

        print("✅ Сообщение отправлено")

        # Ждем ответ
        response_len = int.from_bytes(sock.recv(4), 'big')
        response_data = sock.recv(response_len)
        response = json.loads(response_data.decode('utf-8'))

        print(f"✅ Ответ от сервера: {response}")

        sock.close()
        return True

    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False


if __name__ == "__main__":
    test_connection()