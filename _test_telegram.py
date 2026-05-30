import os, pathlib

p = pathlib.Path(r"E:\Trae\.trae\skills\secops-hub\.env")
for line in p.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    k, v = k.strip(), v.strip().strip('"').strip("'")
    if k and v:
        os.environ.setdefault(k, v)

token = os.environ.get("TELEGRAM_BOT_TOKEN", "NOT FOUND")
chat = os.environ.get("TELEGRAM_CHAT_ID", "NOT FOUND")
print(f"TOKEN={token[:15]}...")
print(f"CHAT={chat}")

import urllib.request, json
url = f"https://api.telegram.org/bot{token}/sendMessage"
body = json.dumps({"chat_id": chat, "text": "[secops-hub] RE-TEST from pipeline debug"}).encode()
req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
resp = urllib.request.urlopen(req, timeout=10)
print(resp.read().decode())
