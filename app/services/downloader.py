import os
import requests
from urllib.parse import urlparse

DOWNLOAD_DIR = "downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def download_file(url):
    r = requests.get(url, timeout=15)
    r.raise_for_status()

    filename = os.path.basename(urlparse(url).path)
    path = os.path.join(DOWNLOAD_DIR, filename)

    with open(path, "wb") as f:
        f.write(r.content)

    return path
