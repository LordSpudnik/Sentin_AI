import pandas as pd
import numpy as np

# Load Monday dataset
df = pd.read_csv(r"D:\CNS Project\CNS Dataset\Monday-WorkingHours.pcap_ISCX.csv")

# Clean column names
df.columns = df.columns.str.strip()

print("Original shape:", df.shape)

# Replace infinite values
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Remove missing values
df = df.dropna()

# Remove duplicates
df = df.drop_duplicates()

print("Cleaned shape:", df.shape)

# Save cleaned dataset
df.to_csv("monday_cleaned.csv", index=False)

print("Monday dataset cleaned and saved!")