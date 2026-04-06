import os
import pickle
from typing import Dict, List, Union

import pandas as pd


class SentinAIInferencer:
    """
    Loads the trained SentinAI model artifact and performs inference
    on one row or multiple rows of feature-engineered traffic data.
    """

    def __init__(self, model_path: str = None):
        """
        Initialize inferencer.

        Args:
            model_path: Path to best_model.pkl
        """
        if model_path is None:
            # Default path based on your repo structure
            model_path = os.path.join("Models", "best_model.pkl")

        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.encoder = None
        self.threshold = None
        self.top_features = None

        self._load_artifact()

    def _load_artifact(self) -> None:
        """Load model, scaler, encoder, threshold, and top features."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model file not found at: {self.model_path}\n"
                f"Please check that best_model.pkl exists in the Models folder."
            )

        with open(self.model_path, "rb") as f:
            artifact = pickle.load(f)

        required_keys = ["model", "scaler", "encoder", "optimal_threshold", "top_features"]
        missing_keys = [key for key in required_keys if key not in artifact]
        if missing_keys:
            raise KeyError(f"Missing keys in model artifact: {missing_keys}")

        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.encoder = artifact["encoder"]
        self.threshold = float(artifact["optimal_threshold"])
        self.top_features = list(artifact["top_features"])

    def get_top_features(self) -> List[str]:
        """Return expected feature list."""
        return self.top_features

    def get_threshold(self) -> float:
        """Return saved optimal threshold."""
        return self.threshold

    def prepare_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Validate and reorder input dataframe to match training-time feature order.

        Args:
            data: Input dataframe

        Returns:
            Prepared dataframe with correct columns/order
        """
        if not isinstance(data, pd.DataFrame):
            raise TypeError("Input data must be a pandas DataFrame.")

        missing_features = [col for col in self.top_features if col not in data.columns]
        if missing_features:
            raise ValueError(
                f"Input data is missing required features: {missing_features}"
            )

        # Keep only required features in exact order used during training
        prepared = data[self.top_features].copy()

        # Convert all features to numeric if possible
        for col in prepared.columns:
            prepared[col] = pd.to_numeric(prepared[col], errors="coerce")

        # Check for nulls created during conversion
        if prepared.isnull().any().any():
            null_cols = prepared.columns[prepared.isnull().any()].tolist()
            raise ValueError(
                f"Null/invalid values detected after numeric conversion in columns: {null_cols}"
            )

        return prepared

    def predict(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Run inference on dataframe.

        Args:
            data: DataFrame containing at least the top_features columns

        Returns:
            DataFrame with:
                - ddos_probability
                - confidence
                - predicted_label
        """
        prepared = self.prepare_features(data)

        # Scale features using saved scaler
        scaled = self.scaler.transform(prepared)

        # Probability of positive class
        # In your model, classes are encoded as BENIGN / DDoS
        probabilities = self.model.predict_proba(scaled)

        # Determine which encoded class corresponds to DDoS
        class_names = list(self.encoder.classes_)
        if "DDoS" not in class_names:
            raise ValueError(
                f"'DDoS' label not found in encoder classes: {class_names}"
            )

        ddos_index = class_names.index("DDoS")
        ddos_prob = probabilities[:, ddos_index]

        # Threshold-based prediction
        predicted_labels = [
            "DDoS" if prob >= self.threshold else "BENIGN"
            for prob in ddos_prob
        ]

        # Confidence = probability of chosen class
        confidences = [
            prob if label == "DDoS" else (1 - prob)
            for prob, label in zip(ddos_prob, predicted_labels)
        ]

        result = pd.DataFrame({
            "ddos_probability": ddos_prob,
            "confidence": confidences,
            "predicted_label": predicted_labels
        })

        return result

    def predict_one(self, row: Union[pd.Series, Dict]) -> Dict:
        """
        Predict on a single row.

        Args:
            row: pandas Series or dict containing feature columns

        Returns:
            Dictionary result
        """
        if isinstance(row, pd.Series):
            row_df = pd.DataFrame([row.to_dict()])
        elif isinstance(row, dict):
            row_df = pd.DataFrame([row])
        else:
            raise TypeError("row must be a pandas Series or dict.")

        result = self.predict(row_df).iloc[0].to_dict()

        return {
            "ddos_probability": float(result["ddos_probability"]),
            "confidence": float(result["confidence"]),
            "predicted_label": str(result["predicted_label"])
        }


if __name__ == "__main__":
    # Simple local test using your processed dataset
    dataset_path = os.path.join("Data", "Processed", "processed_network_dataset.csv")

    if not os.path.exists(dataset_path):
        print(f"Test dataset not found at: {dataset_path}")
    else:
        df = pd.read_csv(dataset_path)

        inferencer = SentinAIInferencer(model_path=os.path.join("models", "best_model.pkl"))

        print("Model loaded successfully.")
        print("Optimal threshold:", inferencer.get_threshold())
        print("Top features:")
        for i, feature in enumerate(inferencer.get_top_features(), start=1):
            print(f"{i}. {feature}")

        # Drop label for testing input
        sample_input = df.drop(columns=["Label"]).head(5)

        predictions = inferencer.predict(sample_input)
        print("\nSample predictions:")
        print(predictions)