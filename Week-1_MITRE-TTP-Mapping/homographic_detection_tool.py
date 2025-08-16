import requests
from bs4 import BeautifulSoup
from PIL import Image
import imagehash
from io import BytesIO
from urllib.parse import urljoin

# ---- CONFIG ----
TRUSTED_LOGO_PATH = "google_logo.png"  # official brand logo file
PHASH_THRESHOLD = 8  # <=8 means likely similar

def get_logo_url(page_url):
    html = requests.get(page_url, timeout=5).text
    soup = BeautifulSoup(html, "lxml")
    for img in soup.find_all("img"):
        src = img.get("src")
        if src and "logo" in src.lower():  # basic heuristic
            return urljoin(page_url, src)
    return None

def compare_logos(trusted_path, suspect_url):
    trusted_logo = Image.open(trusted_path).convert("RGB")
    trusted_hash = imagehash.phash(trusted_logo)

    resp = requests.get(suspect_url, timeout=5)
    suspect_logo = Image.open(BytesIO(resp.content)).convert("RGB")
    suspect_hash = imagehash.phash(suspect_logo)

    diff = trusted_hash - suspect_hash
    return diff

# ---- MAIN ----
page = input("Enter website URL: ").strip()
logo_url = get_logo_url(page)

if not logo_url:
    print("❌ No logo found on the page.")
else:
    print(f"🔍 Found logo: {logo_url}")
    diff_score = compare_logos(TRUSTED_LOGO_PATH, logo_url)
    print(f"Hash difference: {diff_score}")
    if diff_score <= PHASH_THRESHOLD:
        print("⚠️ Possible brand spoof detected!")
    else:
        print("✅ Logo does not closely match trusted brand.")
