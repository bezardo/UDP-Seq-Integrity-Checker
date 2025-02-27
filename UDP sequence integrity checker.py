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
print(f"\nProcessing: {selected_file}\n")

# Read the CSV file
df = pd.read_csv(os.path.join(script_dir, selected_file))

# Ensure required columns exist
if 'Destination' not in df.columns or 'Data' not in df.columns or 'Protocol' not in df.columns:
    print("Missing required columns in the CSV file.")
    exit()

# Filter rows where Destination is in the 239.x.x.x range and Protocol is UDP
df = df[(df['Destination'].astype(str).str.startswith('239.')) & (df['Protocol'] == 'UDP')]

# Remove malformed packets (length <= 65)
df = df[df['Length'] > 65]

# Extract sequence numbers
df['Sequence Number'] = df['Data'].astype(str).apply(extract_sequence_number)

# Process each multicast group
grouped = df.groupby('Destination')
summary = []

for destination, group in grouped:
    print(f"Multicast Group: {destination}")
    sequence_numbers = group['Sequence Number'].dropna().astype(int).tolist()
    packet_numbers = group['No.'].tolist()
    
    out_of_order = False
    for i in range(1, len(sequence_numbers)):
        expected_seq = sequence_numbers[i - 1] + 1
        actual_seq = sequence_numbers[i]
        if expected_seq != actual_seq:
            missed_packets = actual_seq - expected_seq
            print(f"\u274C No. {packet_numbers[i]}: Expected {expected_seq}, got {actual_seq} ({missed_packets} packets missed)")
            summary.append([destination, len(sequence_numbers), "\u274C Out-of-order detected", f"Expected {expected_seq}, got {actual_seq}, No. {packet_numbers[i]}"])
            out_of_order = True
    
    if not out_of_order:
        print(f"\u2705 All sequence numbers are in order!")
        summary.append([destination, len(sequence_numbers), "\u2705 All in order", "-"])

print("\nExporting processed Data ...")

# Save processed file with summary
output_file = os.path.join(script_dir, selected_file.replace('.csv', '.xlsx'))
with pd.ExcelWriter(output_file) as writer:
    df.to_excel(writer, sheet_name="Processed Data", index=False)
    pd.DataFrame(summary, columns=["Destination", "Total Packets", "Status", "Sequence Info"]).to_excel(writer, sheet_name="Summary", index=False)

print(f"\U0001F4C2 Processed file saved as: {output_file}")
