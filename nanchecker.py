import pandas as pd

# Load your extracted CSV file
csv_file = "extracted_data.csv"  # Update this if needed
df = pd.read_csv(csv_file)

# ✅ 1. Check for NaN values in the "Sequence Number" column
nan_count = df["Sequence Number"].isna().sum()
print(f"\n🔍 NaN Values in Sequence Number Column: {nan_count}")

# ✅ 2. Check data type of "Sequence Number" column
sequence_dtype = df["Sequence Number"].dtype
print(f"\n🔍 Data Type of 'Sequence Number' Column: {sequence_dtype}")

# ✅ 3. Check for Non-Integer Values in "Sequence Number"
non_integer_rows = df[~df["Sequence Number"].apply(lambda x: isinstance(x, (int, float)))]
print(f"\n🔍 Non-Integer Values Found: {not non_integer_rows.empty}")

# ✅ 4. Display any rows where "Sequence Number" is NaN
nan_rows = df[df["Sequence Number"].isna()]
if not nan_rows.empty:
    print("\n🔍 Rows with NaN Sequence Numbers:")
    print(nan_rows)

# ✅ 5. Save the problematic rows to a separate CSV file for review
nan_rows.to_csv("nan_sequence_numbers.csv", index=False)
print("\n✅ Problematic rows saved as 'nan_sequence_numbers.csv'.")