import pandas as pd

df = pd.read_csv("data/raw/malicious_phish.csv")
print("Shape:", df.shape)
print("\nFirst rows:")
print(df.head())
print("\nLabel counts:")
print(df["type"].value_counts())