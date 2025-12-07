#!/usr/bin/env python3
"""
Запуск клиента Избирателя для электронного голосования
"""
import sys
import os

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from client.voter_app import VoterClient

if __name__ == "__main__":
    print("=" * 60)
    print("КЛИЕНТ ЭЛЕКТРОННОГО ГОЛОСОВАНИЯ - ИЗБИРАТЕЛЬ")
    print("=" * 60)
    print()

    client = VoterClient()
    client.run()