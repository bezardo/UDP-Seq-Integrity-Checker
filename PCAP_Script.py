import os
import subprocess
import pandas as pd
from datetime import datetime
import pytz  # For timezone conversion

def list_pcap_files():
    """Scans the current directory and lists available .pcap files."""
    pcap_files = [f for f in os.listdir() if f.endswith('.pcap') or f.endswith('.pcapng')]
    return pcap_files

def select_pcap_file(pcap_files):
    """Allows user to select a pcap file from the list."""
    if not pcap_files:
        print("No pcap files found in the current directory.")
        return None
    print("\nAvailable PCAP files:")
    for idx, file in enumerate(pcap_files, 1):
        print(f"{idx}. {file}")
    while True:
        try:
            choice = int(input("\nSelect a file by number: ")) - 1
            if 0 <= choice < len(pcap_files):
                return pcap_files[choice]
            else:
                print("Invalid choice. Try again.")
        except ValueError:
            print("Please enter a valid number.")

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

            # Handle missing values
            df.fillna("No Data", inplace=True)

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
        print(f"\n Analyzing Sequence Numbers for Group: {group}")

        # Filter only packets for this destination group
        group_df = df[df["Destination"] == group]

        if group_df.empty:
            print(f"⚠️ No packets found for {group}. Skipping...")
            continue

        # Group by Source to analyze separately
        grouped = group_df.groupby("Source")

        for source, packets in grouped:
            print(f"\n🔹 Source: {source}")

            # Convert sequence numbers to integers and sort by sequence
            packets = packets.sort_values(by="Sequence Number").reset_index(drop=True)

            sequence_numbers = packets["Sequence Number"].dropna().astype(int).tolist()
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

    print("\n Exporting processed Data ...")

    # Save processed file with summary and original data
    with pd.ExcelWriter(output_excel) as writer:
        df.to_excel(writer, sheet_name="Processed Data", index=False)
        pd.DataFrame(summary, columns=["Destination", "Total Packets", "Status", "Sequence Info"]).to_excel(writer, sheet_name="Summary", index=False)

    print(f"📂 Processed file saved as: {output_excel}")

def main():
    """Main function to run the process."""
    pcap_files = list_pcap_files()
    selected_pcap = select_pcap_file(pcap_files)
    if not selected_pcap:
        return

    df = extract_pcap_data(selected_pcap)
    if df is None:
        return

    # **List Available Multicast Groups**
    unique_groups = sorted(df["Destination"].unique())
    print("\nAvailable Multicast Groups:")
    for idx, group in enumerate(unique_groups, 1):
        print(f"{idx}. {group}")

    # **User selects multiple groups**
    selected_indices = input("\nEnter group numbers to analyze (comma-separated): ").strip()
    try:
        selected_indices = [int(idx) - 1 for idx in selected_indices.split(",")]
        selected_groups = [unique_groups[idx] for idx in selected_indices if 0 <= idx < len(unique_groups)]
    except:
        print("Invalid input! Please enter valid numbers.")
        return

    if not selected_groups:
        print("No valid groups selected. Exiting...")
        return

    print(f"\n Analyzing selected groups: {', '.join(selected_groups)}")

    # **Analyze sequence number order & export summary**
    output_excel = selected_pcap.replace('.pcap', '.xlsx')  # Save Excel file with the same name as the pcap
    detect_sequence_gaps(df, selected_groups, output_excel)

if __name__ == "__main__":
    main()