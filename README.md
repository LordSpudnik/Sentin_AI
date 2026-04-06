# SentinAI — Anomaly-Based Network Intrusion Detection System

> A machine learning-powered IDS that learns normal network behavior and raises alerts when traffic deviates from the learned baseline — no signature databases, no manual rule updates.

---

## Overview

Traditional Intrusion Detection Systems rely on signature matching: they compare observed traffic against a database of known attack patterns. This approach is inherently reactive. It can only catch threats that have already been seen and catalogued, leaving networks exposed to zero-day exploits and novel attack vectors.

**SentinAI** takes a fundamentally different approach. Instead of asking *"does this traffic look like a known attack?"*, it asks *"does this traffic look normal?"*. The system trains on real network flow data to model baseline behavior, then flags any flow that deviates significantly from that baseline — regardless of whether the attack type has ever been seen before.

The project is a complete, end-to-end IDS prototype built as part of the **Cryptography & Network Systems (BCSE309L)** course at VIT. It spans raw data preprocessing, multi-model benchmarking, and a live Security Operations Center (SOC) dashboard with real-time alert visualization.

---

## The Problem

Modern networks face a fundamental mismatch: the threat landscape evolves continuously, but signature-based IDS tools are only as current as their last update. Specific shortcomings include:

- **Zero-day blindness** — no signature exists for an attack that has never been seen before.
- **Alert fatigue** — high false-positive rates from rigid rule matching desensitize analysts to real threats.
- **Operational overhead** — maintaining up-to-date signature databases requires constant expert intervention.
- **Static detection logic** — rule-based systems cannot adapt to gradual shifts in normal traffic patterns.

---

## The Solution

SentinAI addresses these gaps by grounding detection in learned behavior rather than predefined rules. The core idea is straightforward: train a classifier on labeled network flows to distinguish benign traffic from malicious traffic, then deploy that classifier against live or streamed data.

The system introduces several specific design choices to make this practical:

- **CICIDS-2017 dataset** — one of the most comprehensive public benchmarks for network intrusion research, containing labeled flows for DoS, DDoS, Brute Force, Port Scanning, Botnet activity, and benign traffic.
- **Feature engineering** — from 78 available flow-level features, the top 20 are retained through variance and correlation analysis (including `Fwd Packet Length Max`, `Flow Duration`, `Total Fwd Packets`, and TCP flag counts).
- **SMOTE balancing** — in realistic network data, benign traffic accounts for ~99% of all samples. Synthetic Minority Oversampling Technique (SMOTE) is applied to minority attack classes to prevent the model from simply learning to predict "benign" for everything.
- **XGBoost classifier** — selected after benchmarking against Logistic Regression and Random Forest. XGBoost handles the high-dimensional, non-linear patterns in network flow data better than linear methods, and its ensemble structure makes it robust to noisy features.

---

## Architecture

The SentinAI pipeline is organized into three functional layers:

```
Raw Network Traffic (CSV / PCAP)
        │
        ▼
┌─────────────────────────────┐
│  Data Ingestion & Feature   │  ← Parsing, normalization, SMOTE,
│       Engineering           │    scaler fit, top-20 feature selection
└─────────────────────────────┘
        │
        ▼
┌─────────────────────────────┐
│   ML Inference Engine       │  ← XGBoost classifier + optimal threshold
│   (best_model.pkl)          │    outputs prediction + confidence score
└─────────────────────────────┘
        │
        ▼
┌─────────────────────────────┐
│  SOC Dashboard & Rule-Based │  ← Alert generation, severity assignment,
│    Incident Response        │    IP flagging, firewall recommendations
└─────────────────────────────┘
```

All serialized artifacts — trained model, scaler, label encoder, and feature list — are bundled in `best_model.pkl`, making the inference layer self-contained and portable.

---

## Repository Structure

```
├── Data/
│   ├── Processed/
│   │   └── processed_network_dataset.csv   # Cleaned, normalized, SMOTE-balanced dataset
│   ├── Raw/
│   |    └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv  # Raw CICIDS-2017 traffic capture
│   └── top_20_features.csv             # Selected feature subset used for training
├── Metrics/
│   ├── DDos_vs_BENGIN.png        # Class distribution visualization
│   ├── confusion_matrices.png    # Confusion matrices for all three models
│   ├── model_comparison_report.csv # Benchmark metrics across classifiers
│   └── threshold_analysis.png    # Optimal decision threshold analysis
├── Scripts/
│   ├── analysis.ipynb            # Exploratory data analysis notebook
│   ├── analysis_monday.py        # Feature engineering and preprocessing
│   └── main.ipynb                # Model training, evaluation, and export
├── Models/
│   └── best_model.pkl            # Serialized XGBoost model + artifacts
└── SOC/
    ├── alerts_log.csv            # Logged alert events
    ├── app.py                    # SOC dashboard application
    ├── infer.py                  # Inference engine wrapper
    ├── rules.py                  # Rule-based incident response logic
    └── simulator.py              # Network event stream simulator
```

---

## Model Performance

Three classifiers were benchmarked on the CICIDS-2017 test set. Evaluation prioritized **F1-Score** and **Recall** over raw accuracy — in a security context, a missed attack (false negative) is significantly more costly than a false alarm.

| Model | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|
| Logistic Regression | 97.2% | 96.8% | 97.0% | 96.9% |
| Random Forest | 99.9% | 99.9% | 99.9% | 99.9% |
| **XGBoost (selected)** | **100%** | **100%** | **100%** | **1.0000** |

XGBoost was selected as the production model. Key results:

- **F1-Score: 1.0000** and **ROC-AUC: 1.0000** on the held-out test set.
- **Optimal decision threshold: 0.4357**, computed to balance detection sensitivity and specificity.
- **Near-zero False Positives and False Negatives** confirmed via confusion matrix analysis.
- The **Precision-Recall curve** maintains a near-perfect AUC of 1.00 across all thresholds, indicating exceptional model stability — a critical property for high-stakes, real-time environments.

Both ensemble methods substantially outperformed Logistic Regression, confirming that non-linear ensemble approaches are better suited to the complexity of network traffic patterns.

---

## SOC Dashboard

The `soc/` module converts raw model predictions into an operational monitoring interface for security analysts. When the classifier flags a flow as malicious, the rule engine in `rules.py` enriches the alert with:

- **Attacker and target IP addresses**
- **Attack classification** (DoS, Port Scan, etc.)
- **Severity level** (Low / Medium / High / Critical)
- **Recommended action** (e.g., block IP, rate-limit, escalate)

The dashboard (`app.py`) provides real-time visualization of incoming alerts, traffic distribution, top targeted ports, and system-wide metrics. A built-in simulator (`simulator.py`) generates realistic event streams for testing and demonstration without requiring a live network tap.

---

## Live Validation

Beyond benchmark evaluation, the system was validated against real simulated attacks in a controlled network environment:

- A **Kali Linux** machine was configured as the attacker.
- A **Windows host** was configured as the target.
- **Nmap SYN scans** were launched from Kali and captured via **tcpdump** on the target.
- Packet captures confirmed that the SentinAI pipeline correctly flagged the scanning activity as malicious, bridging the gap between academic model performance and practical deployment.

---

## Dataset

**CICIDS-2017** — Canadian Institute for Cybersecurity Intrusion Detection Evaluation Dataset (2017)

This dataset contains labeled network flows generated in a realistic lab environment over five days, covering the following attack categories:

- Benign (background) traffic
- DoS / DDoS (Slowloris, Hulk, GoldenEye, LOIC)
- Web attacks (Brute Force, SQL Injection, XSS)
- Botnet (ARES)
- Port Scanning
- Infiltration

---

## Future Enhancements

- **Adaptive / Online Learning** — enable continuous model retraining from live traffic to track emerging and evolving threat patterns without manual redeployment.
- **Automated Response System** — implement autonomous firewall rule generation and malicious IP blocking upon high-confidence detections, reducing analyst response time to near-zero.
- **Multi-Attack Expansion** — extend detection coverage beyond DDoS to include phishing, ransomware, and insider-threat behavioral patterns.
- **Real-Time Packet Integration** — direct ingestion of live PCAP streams via Scapy or tcpdump into the inference pipeline, eliminating reliance on pre-processed CSV data and enabling true packet-level detection.

---

## Contributors

| Name |
|---|
| Akilan V S |
| Subash Venkat |
| Abhishek Prabakar |
