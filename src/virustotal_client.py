import hashlib, os, time, requests
from dotenv import load_dotenv

load_dotenv()

class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}

    def sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def report(self, file_hash: str) -> dict:
        r = requests.get(f"{self.BASE}/files/{file_hash}", headers=self.headers)
        return r.json() if r.status_code == 200 else {"error": r.status_code}

    def upload(self, path: str) -> dict:
        with open(path, "rb") as f:
            r = requests.post(f"{self.BASE}/files", headers=self.headers,
                              files={"file": (os.path.basename(path), f)})
        return r.json() if r.status_code == 200 else {"error": r.status_code}

    def summarise(self, report: dict) -> dict:
        if "data" not in report:
            return {"detected": 0, "engines": 0, "verdict": "no_report"}
        stats = report["data"]["attributes"].get("last_analysis_stats", {})
        detected = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        return {"detected": detected, "engines": total,
                "verdict": "flagged" if detected else "clean"}