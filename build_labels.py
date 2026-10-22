import json
from pathlib import Path
import pandas as pd

# Paths
CSV_PATH = Path("data/raw/FormAI_dataset_human_readable-V1.csv")
SRC_DIR = Path("data/raw/formai_src")
OUT_PATH = Path("data/labels/ground_truth.json")

OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

# 1. Map the vulnerability types to CWE IDs
cwe_map = {
    "Buffer Overflow": "CWE-787",
    "Use After Free": "CWE-416",
    "Format String": "CWE-134",
    "Memory Leak": "CWE-401",
    "Null Pointer Dereference": "CWE-476",
    "Integer Overflow": "CWE-190",
    "Division by Zero": "CWE-369",
}

# 2. Read the CSV
df = pd.read_csv(CSV_PATH)

# 3. Find all .c files currently in your extracted folder
actual_files = {p.name for p in SRC_DIR.rglob("*.c")}
print(f"Found {len(actual_files)} actual .c files in {SRC_DIR}")

# 4. Build the dictionary
ground_truth = {}
for _, row in df.iterrows():
    fname = row["Filename"]
    if fname in actual_files:
        vuln_type = str(row["Vulnerability type"]).strip()
        cwe = cwe_map.get(vuln_type, "CWE-UNKNOWN")
        ground_truth.setdefault(fname, []).append(cwe)

# 5. Save
with open(OUT_PATH, "w") as f:
    json.dump(ground_truth, f, indent=2)

print(f"✅ Successfully matched {len(ground_truth)} labels and saved to {OUT_PATH}")