import os
import random
import time
from datetime import datetime, timedelta
from typing import Dict, Generator, List, Optional

import pandas as pd

from SOC.infer import SentinAIInferencer
from SOC.rules import build_alert_record


class SentinAITrafficSimulator:
    """
    Simulates a stream of network traffic rows from the processed dataset,
    performs inference, and builds SOC-style alert records.
    """

    def __init__(
        self,
        dataset_path: str = None,
        model_path: str = None,
        log_path: str = None,
        sleep_seconds: float = 0.5
    ):
        if dataset_path is None:
            dataset_path = os.path.join(
                "Data", "Processed", "processed_network_dataset.csv"
            )

        if model_path is None:
            model_path = os.path.join("models", "best_model.pkl")

        if log_path is None:
            log_path = os.path.join("SOC", "alerts_log.csv")

        self.dataset_path = dataset_path
        self.model_path = model_path
        self.log_path = log_path
        self.sleep_seconds = sleep_seconds

        self.df = None
        self.inferencer = SentinAIInferencer(model_path=self.model_path)
        self.top_features = self.inferencer.get_top_features()

        self._load_dataset()

    def _load_dataset(self) -> None:
        """Load processed dataset."""
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(
                f"Processed dataset not found at: {self.dataset_path}"
            )

        self.df = pd.read_csv(self.dataset_path)

        if "Label" not in self.df.columns:
            raise ValueError("Dataset must contain 'Label' column.")

    def _generate_ip(self, internal: bool = False) -> str:
        """
        Generate synthetic IP addresses for dashboard display.
        """
        if internal:
            return f"10.0.0.{random.randint(2, 254)}"
        return f"192.168.1.{random.randint(2, 254)}"

    def _extract_target_port(self, row: pd.Series) -> int:
        """
        Extract Destination Port if available, else return fallback.
        """
        if "Destination Port" in row.index:
            try:
                return int(float(row["Destination Port"]))
            except Exception:
                return 0
        return 0

    def _ensure_log_file(self) -> None:
        """Create log file with headers if it doesn't exist."""
        if not os.path.exists(self.log_path):
            empty_df = pd.DataFrame(columns=[
                "timestamp",
                "attacker_ip",
                "target_ip",
                "target_port",
                "predicted_label",
                "confidence",
                "ddos_probability",
                "severity",
                "recommended_action",
                "true_label"
            ])
            empty_df.to_csv(self.log_path, index=False)

    def append_alert_to_log(self, alert: Dict) -> None:
        """Append one alert row to CSV log."""
        self._ensure_log_file()
        pd.DataFrame([alert]).to_csv(
            self.log_path,
            mode="a",
            header=False,
            index=False
        )

    def simulate_row(self, row: pd.Series, event_time: Optional[datetime] = None) -> Dict:
        """
        Simulate one traffic event:
        - prepare row
        - infer label
        - attach metadata
        - build alert record
        """
        if event_time is None:
            event_time = datetime.now()

        attacker_ip = self._generate_ip(internal=False)
        target_ip = self._generate_ip(internal=True)
        target_port = self._extract_target_port(row)

        # Ground-truth label from dataset
        true_label = str(row["Label"]) if "Label" in row.index else "UNKNOWN"

        # Keep only model features
        feature_row = row[self.top_features].to_dict()

        prediction = self.inferencer.predict_one(feature_row)

        alert = build_alert_record(
            timestamp=event_time.strftime("%Y-%m-%d %H:%M:%S"),
            attacker_ip=attacker_ip,
            target_ip=target_ip,
            target_port=target_port,
            predicted_label=prediction["predicted_label"],
            confidence=prediction["confidence"],
            ddos_probability=prediction["ddos_probability"]
        )

        alert["true_label"] = true_label

        return alert

    def stream_events(
        self,
        num_events: int = 20,
        shuffle: bool = True,
        log_events: bool = False,
        delay: Optional[float] = None
    ) -> Generator[Dict, None, None]:
        """
        Generate alert events one by one, like a real-time traffic stream.

        Args:
            num_events: number of rows to simulate
            shuffle: whether to randomly shuffle dataset before streaming
            log_events: whether to append events to alerts_log.csv
            delay: optional override for sleep_seconds
        """
        if delay is None:
            delay = self.sleep_seconds

        df_stream = self.df.copy()

        if shuffle:
            df_stream = df_stream.sample(frac=1, random_state=42).reset_index(drop=True)

        df_stream = df_stream.head(num_events)

        base_time = datetime.now()

        for idx, (_, row) in enumerate(df_stream.iterrows()):
            event_time = base_time + timedelta(seconds=idx)
            alert = self.simulate_row(row, event_time=event_time)

            if log_events:
                self.append_alert_to_log(alert)

            yield alert

            if delay and delay > 0:
                time.sleep(delay)

    def simulate_batch(
        self,
        num_events: int = 20,
        shuffle: bool = True,
        log_events: bool = False
    ) -> pd.DataFrame:
        """
        Simulate multiple events and return as DataFrame.
        No real-time delay.
        """
        alerts: List[Dict] = []

        df_batch = self.df.copy()

        if shuffle:
            df_batch = df_batch.sample(frac=1, random_state=42).reset_index(drop=True)

        df_batch = df_batch.head(num_events)

        base_time = datetime.now()

        for idx, (_, row) in enumerate(df_batch.iterrows()):
            event_time = base_time + timedelta(seconds=idx)
            alert = self.simulate_row(row, event_time=event_time)

            if log_events:
                self.append_alert_to_log(alert)

            alerts.append(alert)

        return pd.DataFrame(alerts)


if __name__ == "__main__":
    simulator = SentinAITrafficSimulator(
        dataset_path=os.path.join("Data", "Processed", "processed_network_dataset.csv"),
        model_path=os.path.join("models", "best_model.pkl"),
        log_path=os.path.join("SOC", "alerts_log.csv"),
        sleep_seconds=0.2
    )

    print("Streaming 10 simulated events...\n")

    for event in simulator.stream_events(num_events=10, shuffle=True, log_events=True):
        print(event)