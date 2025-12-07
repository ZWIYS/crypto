#!/usr/bin/env python3
"""
Запуск сервера Центра электронного голосования
"""
import sys
import os

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from server.center_app import CenterServer

if __name__ == "__main__":
    print("=" * 60)
    print("СЕРВЕР ЦЕНТРА ЭЛЕКТРОННОГО ГОЛОСОВАНИЯ")
    print("=" * 60)
    print()

    server = CenterServer()
    server.run()