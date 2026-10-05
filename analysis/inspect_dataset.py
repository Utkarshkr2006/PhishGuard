import os
import zipfile
import requests
import pandas as pd
import json

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
ZIP_PATH = os.path.join(DATA_DIR, 'phiusiil_phishing_url_dataset.zip')
UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"

def download_and_extract_dataset():
    """
    Downloads the PhiUSIIL Phishing URL Dataset from UCI repository if not already present.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    
    # Find existing CSV in data/
    csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.csv')]
    if csv_files:
        csv_path = os.path.join(DATA_DIR, csv_files[0])
        print(f"[+] Found existing CSV dataset: {csv_path}")
        return csv_path

    print(f"[*] Downloading dataset from UCI repository: {UCI_ZIP_URL}")
    response = requests.get(UCI_ZIP_URL, stream=True)
    response.raise_for_status()

    with open(ZIP_PATH, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"[+] Download complete: {ZIP_PATH}")

    print("[*] Extracting dataset archive...")
    extracted_csv_path = None
    with zipfile.ZipFile(ZIP_PATH, 'r') as zip_ref:
        zip_ref.extractall(DATA_DIR)
        for file in zip_ref.namelist():
            if file.endswith('.csv'):
                extracted_csv_path = os.path.join(DATA_DIR, file)
                print(f"[+] Extracted CSV file: {file}")

    if not extracted_csv_path:
        # Re-check data dir for csv
        csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith('.csv')]
        if csv_files:
            extracted_csv_path = os.path.join(DATA_DIR, csv_files[0])

    return extracted_csv_path

def inspect_dataset(csv_path):
    """
    Performs full dataset inspection using Pandas.
    """
    print(f"\n==========================================")
    print(f"    PHI USIIL DATASET INSPECTION REPORT")
    print(f"==========================================\n")
    
    df = pd.read_csv(csv_path)
    
    num_rows, num_cols = df.shape
    print(f"1. DATASET SHAPE:")
    print(f"   - Total Rows:    {num_rows:,}")
    print(f"   - Total Columns: {num_cols}\n")

    print(f"2. COLUMN NAMES & DATA TYPES:")
    cols_dtypes = df.dtypes.to_dict()
    for col, dt in cols_dtypes.items():
        print(f"   - {col}: {dt}")
    print()

    print(f"3. MISSING VALUES:")
    missing_series = df.isnull().sum()
    total_missing = missing_series.sum()
    print(f"   - Total Missing Values: {total_missing}")
    if total_missing > 0:
        for col, missing in missing_series[missing_series > 0].items():
            print(f"     * {col}: {missing} missing ({missing/num_rows*100:.2f}%)")
    else:
        print("   - No missing values found across any column.\n")

    print(f"4. DUPLICATE ROWS:")
    num_duplicates = df.duplicated().sum()
    print(f"   - Duplicate Rows: {num_duplicates:,} ({num_duplicates/num_rows*100:.2f}%)\n")

    print(f"5. TARGET / LABEL COLUMN DISTRIBUTION:")
    target_col = None
    possible_targets = ['label', 'Label', 'class', 'Class', 'target', 'Target', 'status', 'Status']
    for candidate in possible_targets:
        if candidate in df.columns:
            target_col = candidate
            break

    if target_col:
        unique_vals = df[target_col].unique().tolist()
        val_counts = df[target_col].value_counts().to_dict()
        print(f"   - Target Column Name: '{target_col}'")
        print(f"   - Unique Values: {unique_vals}")
        print(f"   - Class Counts & Percentages:")
        for val, count in val_counts.items():
            pct = (count / num_rows) * 100
            label_desc = "Legitimate" if val == 1 else "Phishing" if val == 0 else f"Value {val}"
            print(f"     * {val} ({label_desc}): {count:,} ({pct:.2f}%)")
    else:
        print("   - Target column could not be automatically identified.")
    print()

    print(f"6. BASIC STATISTICS FOR NUMERICAL FEATURES:")
    stats_df = df.describe().T[['mean', 'std', 'min', '50%', 'max']]
    print(stats_df.to_string())
    print()

    # Save summary report to JSON for programmatic reference
    summary = {
        "num_rows": int(num_rows),
        "num_cols": int(num_cols),
        "columns": list(df.columns),
        "dtypes": {k: str(v) for k, v in cols_dtypes.items()},
        "total_missing": int(total_missing),
        "num_duplicates": int(num_duplicates),
        "target_column": target_col,
        "class_distribution": {str(k): int(v) for k, v in val_counts.items()} if target_col else {}
    }
    
    summary_json_path = os.path.join(DATA_DIR, "dataset_inspection_summary.json")
    with open(summary_json_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Summary report saved to {summary_json_path}")

    return df

if __name__ == '__main__':
    csv_file = download_and_extract_dataset()
    if csv_file and os.path.exists(csv_file):
        inspect_dataset(csv_file)
    else:
        print("[!] Error: CSV dataset could not be located.")
