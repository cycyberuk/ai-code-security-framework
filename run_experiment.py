import json
import random
from pathlib import Path
import sys
import pandas as pd
from src.deepseek_client import DeepSeekClient
from src.virustotal_client import VirusTotalClient
from src import static_analysis
from sklearn.metrics import precision_recall_fscore_support

# --- CONFIGURATION ---
DATA = Path("data")
RESULTS = Path("results")
RESULTS.mkdir(exist_ok=True)

# Set to 100 for the paper. (Increase to 200 if you have API budget).
SAMPLE_SIZE = 100 

def main():
    gt_path = DATA / "labels" / "ground_truth.json"
    src_dir = DATA / "raw" / "formai_src"

    if not gt_path.exists():
        print(f"❌ Missing {gt_path}. Run build_labels.py first.")
        sys.exit(1)

    print("Loading ground truth labels...")
    gt = json.load(open(gt_path))
    
    # 1. Gather all valid files
    all_files = sorted([p for p in src_dir.rglob("*.c") if p.name in gt])
    print(f"✅ Found {len(all_files)} valid labeled .c files in dataset.")

    # 2. Shuffle to get a representative sample (vulnerable and secure)
    random.seed(42)  # Fixed seed ensures reproducibility for the paper
    random.shuffle(all_files)
    
    # 3. Select the sample
    files = all_files[:SAMPLE_SIZE]
    print(f"✅ Selected a random sample of {len(files)} files for analysis.\n")

    ds, vt = DeepSeekClient(), VirusTotalClient()

    gt_list, ds_preds, st_preds = [], [], []
    api_errors = 0

    print("Starting analysis (this will take a few minutes)...")
    for i, path in enumerate(files, 1):
        code = path.read_text(errors="ignore")
        
        # Ground truth (list of CWEs)
        gt_cwes = set(gt[path.name])
        gt_list.append(gt_cwes)

        # 1. DeepSeek Prediction
        try:
            pred = ds.classify_cwe(code, path.name)
            ds_cwes = {c["cwe_id"] for c in pred.get("cwes", [])}
            ds_preds.append(ds_cwes)
        except Exception as e:
            # If API fails (e.g. insufficient balance), catch it and move on
            api_errors += 1
            if api_errors <= 3: # Only print the first few errors to avoid flooding
                print(f"⚠️ DeepSeek API Error on {path.name}: {e}")
            ds_preds.append(set())

        # 2. Static Analysis Prediction
        st_cwes = {f["cwe"] for f in static_analysis.detect(code)["findings"]}
        st_preds.append(st_cwes)

        if i % 10 == 0:
            print(f"  Processed {i}/{len(files)} files...")

    if api_errors > 0:
        print(f"\n⚠️ WARNING: {api_errors} DeepSeek API calls failed. Please check your balance/connection.")

    # --- EVALUATION ---
    # We evaluate based on whether *any* vulnerability was found (Binary classification)
    # If you want per-CWE metrics, you would loop through the CWE list instead.
    y_true = [1 if len(s) > 0 else 0 for s in gt_list]
    ds_y   = [1 if len(s) > 0 else 0 for s in ds_preds]
    st_y   = [1 if len(s) > 0 else 0 for s in st_preds]

    # Calculate metrics (Precision, Recall, F1)
    ds_p, ds_r, ds_f1, _ = precision_recall_fscore_support(y_true, ds_y, average="binary", zero_division=0)
    st_p, st_r, st_f1, _ = precision_recall_fscore_support(y_true, st_y, average="binary", zero_division=0)

    results = {
        "metadata": {
            "n_samples": len(files),
            "random_seed": 42,
            "api_errors": api_errors
        },
        "deepseek": {
            "precision": round(ds_p, 4), 
            "recall": round(ds_r, 4), 
            "f1": round(ds_f1, 4)
        },
        "static": {
            "precision": round(st_p, 4), 
            "recall": round(st_r, 4), 
            "f1": round(st_f1, 4)
        }
    }
    
    # Save to JSON
    out_file = RESULTS / "metrics.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    # --- PRINT FINAL RESULTS ---
    print("\n" + "="*40)
    print(" 🎯 FINAL EXPERIMENT RESULTS 🎯")
    print("="*40)
    print(f"Sample Size : {len(files)} files")
    print(f"API Errors  : {api_errors}")
    print("-" * 40)
    print(f"{'Tool':<12} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10}")
    print("-" * 40)
    print(f"{'DeepSeek':<12} | {ds_p:<10.3f} | {ds_r:<10.3f} | {ds_f1:<10.3f}")
    print(f"{'Static':<12} | {st_p:<10.3f} | {st_r:<10.3f} | {st_f1:<10.3f}")
    print("="*40)
    print(f"✅ Detailed results saved to: {out_file}")
    print("Use these exact numbers in Section VI of your paper!\n")

if __name__ == "__main__":
    main()