import os
import pandas as pd

# Function to extract sequence number from Data column
def extract_sequence_number(hex_data):
    try:
        extracted_hex = hex_data[20:28]  # Skip first 20 characters, take next 8
        return int(extracted_hex, 16)  # Convert hex to decimal
    except:
        return None

# Get all CSV files in the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))
csv_files = [f for f in os.listdir(script_dir) if f.endswith('.csv')]

# Display available files
if not csv_files:
    print("No CSV files found in the directory.")
    exit()

print("Available CSV files:")
for idx, file in enumerate(csv_files):
    print(f"{idx + 1}. {file}")

# Let user select a file
file_index = int(input("Enter the number of the file to process: ")) - 1
if file_index not in range(len(csv_files)):
    print("Invalid selection.")
    exit()

selected_file = csv_files[file_index]
print(f"\nProcessing: {selected_file}")

# Read the CSV file
df = pd.read_csv(os.path.join(script_dir, selected_file), dtype=str)

# Ensure required columns exist
required_columns = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Data', 'Info']
missing_columns = [col for col in required_columns if col not in df.columns]
if missing_columns:
    print(f"Missing required columns in the CSV file: {missing_columns}")
    exit()

# Convert numeric columns to integers (handling NaN)
df['No.'] = pd.to_numeric(df['No.'], errors='coerce')
df['Length'] = pd.to_numeric(df['Length'], errors='coerce')

# Remove malformed packets (length ≤ 65, non-UDP, or malformed hex patterns)
malformed_df = df[
    (df['Length'] <= 65) | 
    (df['Protocol'] != 'UDP') | 
    (df['Data'].str.startswith('3100', na=False))  # Extra filter for malformed packets
]
df = df[~df.index.isin(malformed_df.index)]  # Remove malformed rows

# Save malformed packets separately
malformed_file = os.path.join(script_dir, f"malformed_{selected_file.replace('.csv', '.xlsx')}")
malformed_df.to_excel(malformed_file, index=False)
print(f"\nMalformed packets saved as: {malformed_file}")

# Filter rows where Destination is in the 239.x.x.x range
df = df[df['Destination'].str.startswith('239.')]

# Extract sequence numbers while maintaining CSV order
df['Sequence Number'] = df['Data'].astype(str).apply(extract_sequence_number)

# Evaluate sequence integrity per destination group (preserving CSV order)
grouped = df.groupby('Destination', sort=False)  # No sorting

for dest, group in grouped:
    print(f"\nMulticast Group: {dest}")
    prev_seq = None
    for idx, row in group.iterrows():
        current_seq = row['Sequence Number']
        if prev_seq is not None and current_seq != prev_seq + 1:
            missing_count = current_seq - prev_seq - 1
            print(f"❌ No. {row['No.']}: Expected {prev_seq + 1}, got {current_seq} ({missing_count} packets missed)")
        prev_seq = current_seq
    print("✅ All sequence numbers are in order!")

# Save processed file as Excel (.xlsx) in the same order
processed_file = os.path.join(script_dir, selected_file.replace('.csv', '.xlsx'))
df.to_excel(processed_file, index=False)
print(f"\n✅ Full processed file saved as: {processed_file}")