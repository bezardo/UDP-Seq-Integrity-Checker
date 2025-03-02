import os
import subprocess
import pandas as pd
from datetime import datetime
import pytz  # For timezone conversion

def list_pcap_files():
    """Scans the current directory and lists available .pcap files."""
    pcap_files = [f for f in os.listdir() if f.endswith('.pcap') or f.endswith('.pcapng')]
    return pcap_files

def select_pcap_files(pcap_files):
    """Allows user to select multiple pcap files from the list."""
    if not pcap_files:
        print("No pcap files found in the current directory.")
        return []

    print("\nAvailable PCAP files:")
    for idx, file in enumerate(pcap_files, 1):
        print(f"{idx}. {file}")

    selected_files = input("\nEnter file numbers to process (comma-separated): ").strip()
    try:
        selected_indices = [int(idx) - 1 for idx in selected_files.split(",")]
        selected_pcap_files = [pcap_files[idx] for idx in selected_indices if 0 <= idx < len(pcap_files)]
    except:
        print("Invalid input! Please enter valid numbers.")
        return []

    return selected_pcap_files

def hex_to_decimal(hex_value):
    """Convert a 4-byte hex string to decimal."""
    try:
        return int(hex_value, 16)
    except ValueError:
        return None

def extract_sequence_number(hex_data):
    """Extract sequence number from Data column."""
    if isinstance(hex_data, str) and len(hex_data) >= 28:
        seq_hex = hex_data[20:28]  # Extract 4 bytes after skipping first 10 bytes
        return hex_to_decimal(seq_hex)
    return None

def extract_pcap_data(pcap_file):
    """Extracts only UDP packets and returns a DataFrame."""
    tshark_cmd = [
        "tshark", 
        "-r", pcap_file, 
        "-Y", "udp",  # Filter only UDP packets
        "-T", "fields",
        "-E", "separator=,", 
        "-E", "header=y",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "frame.len",  # Extract packet length
        "-e", "data.data"
    ]
    try:
        result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)
        output_lines = result.stdout.splitlines()

        if output_lines:
            # Convert to DataFrame and assign column names
            data = [line.split(",") for line in output_lines if line.strip()]
            df = pd.DataFrame(data[1:], columns=["No.", "Time", "Source", "Destination", "Length", "Data"])

            # Convert Epoch time to local time format
            def convert_time(epoch_str):
                try:
                    epoch = float(epoch_str)
                    dt = datetime.fromtimestamp(epoch, pytz.timezone("Asia/Kolkata"))  # Change to local timezone
                    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # Retaining milliseconds
                except ValueError:
                    return "Invalid Time"
            
            df["Time"] = df["Time"].apply(convert_time)

            # Convert Length column to integer
            df["Length"] = pd.to_numeric(df["Length"], errors="coerce")

            # **Filter Destination IP (only keep 239.50.x.x)**
            df = df[df["Destination"].str.startswith("239.50.")]

            # **Remove malformed packets (deformed filtering)**
            df = df[~(df["Data"].str.startswith("3100", na=False) & (df["Length"] <= 65))]

            # **Extract Sequence Number**
            df["Sequence Number"] = df["Data"].apply(extract_sequence_number)

            # Ensure 'Sequence Number' is fully numeric before sorting
            df["Sequence Number"] = pd.to_numeric(df["Sequence Number"], errors="coerce")
            
            # Drop NaN values (invalid sequence numbers)
            df = df.dropna(subset=["Sequence Number"])
            
            # Convert to integer after ensuring valid numeric values
            df["Sequence Number"] = df["Sequence Number"].astype(int)

            return df
        else:
            print("No UDP packets extracted from the pcap file.")
            return None

    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        return None

def detect_sequence_gaps(df, selected_groups, output_excel):
    """Detects sequence number gaps for selected multicast groups and saves summary to Excel."""
    summary = []

    for group in selected_groups:
        print(f"\n🔍 Analyzing Sequence Numbers for Group: {group}")

        # Filter only packets for this destination group
        group_df = df[df["Destination"] == group]

        if group_df.empty:
            print(f"⚠️ No packets found for {group}. Skipping...")
            continue

        # Group by Source to analyze separately
        grouped = group_df.groupby("Source")

        for source, packets in grouped:
            print(f"\n🔹 Source: {source}")

            # Ensure 'Sequence Number' is fully numeric and handle missing values
            packets["Sequence Number"] = pd.to_numeric(packets["Sequence Number"], errors="coerce")

            # Drop completely invalid sequence numbers before sorting
            packets = packets.dropna(subset=["Sequence Number"])

            # Convert to integer after ensuring valid numeric values
            packets["Sequence Number"] = packets["Sequence Number"].astype(int)

            # Now, sorting will work properly
            packets = packets.sort_values(by="Sequence Number").reset_index(drop=True)

            sequence_numbers = packets["Sequence Number"].tolist()
            packet_numbers = packets["No."].tolist()

            out_of_order = False
            for i in range(1, len(sequence_numbers)):
                expected_seq = sequence_numbers[i - 1] + 1
                actual_seq = sequence_numbers[i]
                if expected_seq != actual_seq:
                    missed_packets = actual_seq - expected_seq
                    print(f"❌ No. {packet_numbers[i]}: Expected {expected_seq}, got {actual_seq} ({missed_packets} packets missed)")
                    summary.append([group, len(sequence_numbers), "❌ Out-of-order detected",
                                    f"Expected {expected_seq}, got {actual_seq}, No. {packet_numbers[i]}"])
                    out_of_order = True

            if not out_of_order:
                print("✅ All sequence numbers are in order!")
                summary.append([group, len(sequence_numbers), "✅ All in order", "-"])

    print("\n📂 Exporting processed Data ...")

    # Save processed file with summary and original data
    with pd.ExcelWriter(output_excel) as writer:
        df.to_excel(writer, sheet_name="Processed Data", index=False)
        pd.DataFrame(summary, columns=["Destination", "Total Packets", "Status", "Sequence Info"]).to_excel(writer, sheet_name="Summary", index=False)

    print(f"📂 Processed file saved as: {output_excel}")

def process_pcap_files(selected_pcap_files, selected_groups_per_pcap):
    """Processes multiple PCAP files one by one with the selected multicast groups."""
    for pcap_file in selected_pcap_files:
        print(f"\n📂 Processing: {pcap_file}")
        df = extract_pcap_data(pcap_file)
        if df is None:
            continue

        selected_groups = selected_groups_per_pcap[pcap_file]
        print(f"\n📊 Analyzing selected groups: {', '.join(selected_groups)}")

        # **Analyze sequence number order & export summary**
        output_excel = pcap_file.replace('.pcap', '.xlsx')  # Save Excel file with the same name as the pcap
        detect_sequence_gaps(df, selected_groups, output_excel)

def main():
    """Main function to run the process."""
    pcap_files = list_pcap_files()
    selected_pcap_files = select_pcap_files(pcap_files)
    if not selected_pcap_files:
        return

    selected_groups_per_pcap = {}
    for pcap_file in selected_pcap_files:
        df = extract_pcap_data(pcap_file)
        if df is None:
            continue

        unique_groups = sorted(df["Destination"].unique())
        print(f"\nAvailable Multicast Groups for {pcap_file}:")
        for idx, group in enumerate(unique_groups, 1):
            print(f"{idx}. {group}")

        selected_indices = input(f"\nEnter group numbers to analyze for {pcap_file} (comma-separated): ").strip()
        selected_groups = [unique_groups[int(idx) - 1] for idx in selected_indices.split(",") if 0 <= int(idx) - 1 < len(unique_groups)]
        selected_groups_per_pcap[pcap_file] = selected_groups

    process_pcap_files(selected_pcap_files, selected_groups_per_pcap)

if __name__ == "__main__":
    main()
