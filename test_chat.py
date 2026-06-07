import requests
import json
import time

url = "http://127.0.0.1:8000/api/chat"
payload = {"message": "hello", "session_id": "test1"}

with requests.post(url, json=payload, stream=True) as r:
    for line in r.iter_lines():
        if line:
            print(line.decode('utf-8'))
