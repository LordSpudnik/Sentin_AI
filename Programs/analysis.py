import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


# -----------------------------
# 1. Load Dataset
# -----------------------------
df = pd.read_csv(r"D:\CNS Project\CNS Dataset\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# Remove unwanted spaces in column names
df.columns = df.columns.str.strip()

print("Original dataset shape:", df.shape)


# -----------------------------
# 2. Data Cleaning
# -----------------------------

# Replace infinite values with NaN
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Remove missing values
df = df.dropna()

# Remove duplicate rows
df = df.drop_duplicates()

print("Cleaned dataset shape:", df.shape)


# -----------------------------
# 3. Separate Features & Label
# -----------------------------
X = df.drop('Label', axis=1)
y = df['Label']


# -----------------------------
# 4. Encode Labels
# -----------------------------
encoder = LabelEncoder()
y = encoder.fit_transform(y)


# -----------------------------
# 5. Train Random Forest Model
# -----------------------------
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)


# -----------------------------
# 6. Feature Importance
# -----------------------------
importance = pd.Series(model.feature_importances_, index=X.columns)

# Sort features
top_features = importance.sort_values(ascending=False)

print("\nTop 20 Important Features:\n")
print(top_features.head(20))


# Save top features list
top_features.head(20).to_csv("top_20_features.csv")
print("\nTop 20 features saved to top_20_features.csv")


# -----------------------------
# 7. Visualization
# -----------------------------
plt.figure()

df['Label'].value_counts().plot(kind='bar')

plt.title("Attack Distribution")
plt.xlabel("Traffic Type")
plt.ylabel("Count")

plt.show()


# -----------------------------
# 8. Create Final Dataset with Top Features
# -----------------------------
top20 = top_features.head(20).index

# Select only important features
X_top = X[top20]

# Add label column
final_df = X_top.copy()
final_df['Label'] = df['Label']

print("\nFinal dataset shape:", final_df.shape)


# -----------------------------
# 9. Save Processed Dataset
# -----------------------------
final_df.to_csv("processed_network_dataset.csv", index=False)

print("Processed dataset saved as processed_network_dataset.csv")