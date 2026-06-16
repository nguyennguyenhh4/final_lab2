"""
plot_runs_lab2_fixed.py — Convert Lab 2 benchmark CSV to PNG plots.

Compatible with bench.cpp CSV format:
config,size,payload_bytes,mean_ms,median_ms,stddev_ms,ci95_ms,throughput_MBs

Usage:
  python plot_runs_lab2_fixed.py --csv results.csv
  python plot_runs_lab2_fixed.py --csv results.csv --out-dir plots
"""

import argparse
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt

REQUIRED_COLUMNS = {
    "config",
    "size",
    "payload_bytes",
    "mean_ms",
    "median_ms",
    "stddev_ms",
    "ci95_ms",
    "throughput_MBs",
}


def load_csv(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {path}")

    df = pd.read_csv(path)
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        raise ValueError(
            "CSV format does not match Lab 2 bench.cpp output. "
            f"Missing columns: {sorted(missing)}\n"
            "Expected columns: " + ", ".join(sorted(REQUIRED_COLUMNS))
        )

    df = df.copy()
    df["payload_bytes"] = pd.to_numeric(df["payload_bytes"], errors="coerce")
    df["mean_ms"] = pd.to_numeric(df["mean_ms"], errors="coerce")
    df["median_ms"] = pd.to_numeric(df["median_ms"], errors="coerce")
    df["ci95_ms"] = pd.to_numeric(df["ci95_ms"], errors="coerce")
    df["throughput_MBs"] = pd.to_numeric(df["throughput_MBs"], errors="coerce")
    df = df.dropna(subset=["payload_bytes", "mean_ms", "throughput_MBs"])
    df = df.sort_values(["config", "payload_bytes"])
    return df


def plot_throughput(df: pd.DataFrame, out_dir: Path) -> Path:
    out_path = out_dir / "lab2_throughput_by_size.png"

    plt.figure(figsize=(12, 6))
    for cfg, group in df.groupby("config", sort=False):
        plt.plot(group["size"], group["throughput_MBs"], marker="o", label=cfg)

    plt.title("Lab 2 AES-CTR Throughput by Payload Size")
    plt.xlabel("Payload size")
    plt.ylabel("Throughput (MB/s)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()
    return out_path


def plot_latency(df: pd.DataFrame, out_dir: Path) -> Path:
    out_path = out_dir / "lab2_latency_by_size.png"

    plt.figure(figsize=(12, 6))
    for cfg, group in df.groupby("config", sort=False):
        plt.errorbar(
            group["size"],
            group["mean_ms"],
            yerr=group["ci95_ms"],
            marker="o",
            capsize=4,
            label=cfg,
        )

    plt.title("Lab 2 AES-CTR Mean Latency by Payload Size (95% CI)")
    plt.xlabel("Payload size")
    plt.ylabel("Mean latency (ms)")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path, dpi=300)
    plt.close()
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert Lab 2 benchmark CSV to PNG plots.")
    parser.add_argument("--csv", default="results.csv", help="Input CSV exported by bench.exe")
    parser.add_argument("--out-dir", default=".", help="Directory for PNG output files")
    args = parser.parse_args()

    csv_path = Path(args.csv)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_csv(csv_path)
    paths = [plot_throughput(df, out_dir), plot_latency(df, out_dir)]

    print("Saved PNG files:")
    for path in paths:
        print(f"- {path}")


if __name__ == "__main__":
    main()
