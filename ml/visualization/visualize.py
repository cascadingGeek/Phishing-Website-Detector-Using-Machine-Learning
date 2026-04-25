"""
Generate visualizations for the phishing detection dataset and model.

Produces four plots saved to ml/visualization/plots/:
  01_class_distribution.png   — Dataset class balance (bar + pie)
  02_feature_distribution.png — Per-feature value breakdown by class
  03_correlation_heatmap.png  — Pairwise feature correlation matrix
  04_feature_importance.png   — Permutation importance from trained SVM

Usage:
    uv run --group viz python -m ml.visualization.visualize
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")  # non-interactive backend — no GUI window needed

from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.inspection import permutation_importance
from sklearn.model_selection import train_test_split

DATASET_PATH = Path(__file__).parents[2] / "ml" / "datasets" / "dataset.csv"
ARTIFACT_DIR = Path(__file__).parents[2] / "app" / "artifacts" / "v1"
OUTPUT_DIR = Path(__file__).parent / "plots"

FEATURE_COLUMNS = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
]

LABEL_MAP = {-1: "Legitimate", 1: "Phishing"}
PALETTE = {"Legitimate": "#2ecc71", "Phishing": "#e74c3c"}

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "#f8f9fa",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "font.family": "sans-serif",
})


def load_data() -> tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    df = pd.read_csv(DATASET_PATH)
    X = df[FEATURE_COLUMNS]
    y = df["Result"]
    df_labeled = df.copy()
    df_labeled["Class"] = y.map(LABEL_MAP)
    return X, y, df_labeled


def plot_class_distribution(df_labeled: pd.DataFrame, output_dir: Path) -> None:
    counts = df_labeled["Class"].value_counts().reindex(["Legitimate", "Phishing"])
    total = len(df_labeled)

    fig = plt.figure(figsize=(14, 5))
    fig.suptitle("Dataset Class Distribution", fontsize=17, fontweight="bold", y=1.01)
    gs = gridspec.GridSpec(1, 3, figure=fig, width_ratios=[2, 2, 3], wspace=0.35)

    # --- Bar chart ---
    ax_bar = fig.add_subplot(gs[0])
    colors = [PALETTE[c] for c in counts.index]
    bars = ax_bar.bar(counts.index, counts.values, color=colors, edgecolor="white",
                      linewidth=1.5, width=0.5)
    for bar, count in zip(bars, counts.values):
        ax_bar.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + total * 0.01,
            f"{count:,}\n({count / total * 100:.1f}%)",
            ha="center", va="bottom", fontsize=11, fontweight="bold",
        )
    ax_bar.set_ylim(0, counts.max() * 1.22)
    ax_bar.set_title("Sample Count per Class", fontsize=12, pad=10)
    ax_bar.set_ylabel("Number of Samples", fontsize=10)
    ax_bar.set_xlabel("Class", fontsize=10)
    ax_bar.tick_params(labelsize=10)

    # --- Pie chart ---
    ax_pie = fig.add_subplot(gs[1])
    wedges, texts, autotexts = ax_pie.pie(
        counts.values,
        labels=counts.index,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        wedgeprops={"edgecolor": "white", "linewidth": 2},
        textprops={"fontsize": 11},
    )
    for at in autotexts:
        at.set_fontweight("bold")
        at.set_fontsize(12)
    ax_pie.set_title("Class Proportion", fontsize=12, pad=10)

    # --- Summary stats table ---
    ax_tbl = fig.add_subplot(gs[2])
    ax_tbl.axis("off")
    table_data = [
        ["Metric", "Legitimate", "Phishing"],
        ["Count", f"{counts['Legitimate']:,}", f"{counts['Phishing']:,}"],
        ["Share", f"{counts['Legitimate']/total*100:.1f}%", f"{counts['Phishing']/total*100:.1f}%"],
        ["Total samples", f"{total:,}", ""],
        ["Features", "30", ""],
        ["Label encoding", "-1", "1"],
    ]
    tbl = ax_tbl.table(
        cellText=table_data[1:],
        colLabels=table_data[0],
        loc="center",
        cellLoc="center",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(11)
    tbl.scale(1.3, 1.8)
    for (row, col), cell in tbl.get_celld().items():
        if row == 0:
            cell.set_facecolor("#34495e")
            cell.set_text_props(color="white", fontweight="bold")
        elif col == 1:
            cell.set_facecolor("#d5f5e3")
        elif col == 2:
            cell.set_facecolor("#fadbd8")
    ax_tbl.set_title("Dataset Summary", fontsize=12, pad=10)

    plt.tight_layout()
    path = output_dir / "01_class_distribution.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"  Saved: {path}")


def plot_feature_distribution(df_labeled: pd.DataFrame, output_dir: Path) -> None:
    n_features = len(FEATURE_COLUMNS)
    ncols = 5
    nrows = (n_features + ncols - 1) // ncols

    fig, axes = plt.subplots(nrows, ncols, figsize=(22, nrows * 3.2))
    fig.suptitle(
        "Feature Value Distribution by Class\n"
        "Feature values: −1 = phishing indicator  |  0 = uncertain  |  1 = legitimate indicator",
        fontsize=14, fontweight="bold", y=1.01,
    )
    axes_flat = axes.flatten()

    for i, feature in enumerate(FEATURE_COLUMNS):
        ax = axes_flat[i]
        values = sorted(df_labeled[feature].unique())
        x = np.arange(len(values))
        width = 0.38

        for j, cls in enumerate(["Legitimate", "Phishing"]):
            group = df_labeled[df_labeled["Class"] == cls]
            cnt = group[feature].value_counts().reindex(values, fill_value=0)
            offset = (j - 0.5) * width
            ax.bar(x + offset, cnt.values, width, label=cls,
                   color=PALETTE[cls], alpha=0.88, edgecolor="white", linewidth=0.8)

        ax.set_title(feature, fontsize=8, fontweight="bold", pad=4)
        ax.set_xticks(x)
        ax.set_xticklabels([str(v) for v in values], fontsize=8)
        ax.tick_params(axis="y", labelsize=7)
        ax.set_xlabel("Value", fontsize=7, labelpad=2)
        if i == 0:
            ax.legend(fontsize=7, loc="upper right")

    for ax in axes_flat[n_features:]:
        ax.set_visible(False)

    # Single shared legend at figure level
    handles = [
        plt.Rectangle((0, 0), 1, 1, color=PALETTE["Legitimate"], label="Legitimate"),
        plt.Rectangle((0, 0), 1, 1, color=PALETTE["Phishing"], label="Phishing"),
    ]
    fig.legend(handles=handles, loc="lower center", ncol=2, fontsize=11,
               bbox_to_anchor=(0.5, -0.01), frameon=True)

    plt.tight_layout()
    path = output_dir / "02_feature_distribution.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"  Saved: {path}")


def plot_correlation_heatmap(X: pd.DataFrame, output_dir: Path) -> None:
    corr = X.corr()

    fig, ax = plt.subplots(figsize=(15, 13))
    mask = np.triu(np.ones_like(corr, dtype=bool))

    cmap = sns.diverging_palette(10, 130, as_cmap=True)
    sns.heatmap(
        corr,
        mask=mask,
        annot=True,
        fmt=".2f",
        cmap=cmap,
        center=0,
        vmin=-1,
        vmax=1,
        square=True,
        linewidths=0.4,
        ax=ax,
        annot_kws={"size": 6},
        cbar_kws={"shrink": 0.75, "label": "Pearson Correlation"},
    )
    ax.set_title(
        "Feature Correlation Heatmap\n(lower triangle only; red = positive, green = negative)",
        fontsize=14, fontweight="bold", pad=16,
    )
    ax.set_xticklabels(ax.get_xticklabels(), rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=8)

    plt.tight_layout()
    path = output_dir / "03_correlation_heatmap.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"  Saved: {path}")


def plot_feature_importance(X: pd.DataFrame, y: pd.Series, output_dir: Path) -> None:
    model = joblib.load(ARTIFACT_DIR / "model.joblib")
    scaler = joblib.load(ARTIFACT_DIR / "scaler.joblib")

    _, X_test, _, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    X_test_scaled = scaler.transform(X_test)

    print("  Computing permutation importance (may take ~30 s)…")
    result = permutation_importance(
        model, X_test_scaled, y_test,
        n_repeats=15, random_state=42, n_jobs=-1,
    )

    importances = pd.Series(result.importances_mean, index=FEATURE_COLUMNS)
    errors = pd.Series(result.importances_std, index=FEATURE_COLUMNS)
    order = importances.sort_values(ascending=True)
    errs_sorted = errors.loc[order.index]

    colors = ["#e74c3c" if v > 0.001 else "#bdc3c7" for v in order.values]

    fig, ax = plt.subplots(figsize=(11, 13))
    bars = ax.barh(
        order.index, order.values,
        xerr=errs_sorted.values,
        color=colors, edgecolor="white", height=0.65,
        error_kw={"ecolor": "#555", "capsize": 3, "linewidth": 1},
    )
    ax.set_title(
        "Feature Importance — Permutation Importance (RBF SVM)\n"
        "Each bar shows mean accuracy drop when the feature is randomly shuffled",
        fontsize=13, fontweight="bold", pad=14,
    )
    ax.set_xlabel("Mean Accuracy Decrease (± std over 15 repeats)", fontsize=10)
    ax.axvline(0, color="#333", linewidth=0.8, linestyle="--")
    ax.tick_params(axis="y", labelsize=9)
    ax.tick_params(axis="x", labelsize=9)

    for bar, val in zip(bars, order.values):
        ax.text(
            max(val, 0) + 0.0005,
            bar.get_y() + bar.get_height() / 2,
            f"{val:.4f}",
            va="center", ha="left", fontsize=8, color="#333",
        )

    # Colour legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor="#e74c3c", label="Important feature"),
        Patch(facecolor="#bdc3c7", label="Low / no importance"),
    ]
    ax.legend(handles=legend_elements, fontsize=9, loc="lower right")

    plt.tight_layout()
    path = output_dir / "04_feature_importance.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.show()
    print(f"  Saved: {path}")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    sns.set_theme(style="whitegrid")

    print(f"Loading dataset from {DATASET_PATH} …")
    X, y, df_labeled = load_data()
    print(f"  {len(X):,} samples · {len(FEATURE_COLUMNS)} features")
    print(f"  Class counts: {dict(y.value_counts().rename(LABEL_MAP))}\n")

    print("[1/4] Class distribution …")
    plot_class_distribution(df_labeled, OUTPUT_DIR)

    print("[2/4] Feature value distributions …")
    plot_feature_distribution(df_labeled, OUTPUT_DIR)

    print("[3/4] Correlation heatmap …")
    plot_correlation_heatmap(X, OUTPUT_DIR)

    print("[4/4] Feature importance …")
    plot_feature_importance(X, y, OUTPUT_DIR)

    print(f"\nAll plots saved to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
