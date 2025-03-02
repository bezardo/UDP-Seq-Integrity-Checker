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

            # Ensure numeric columns remain numeric
            numeric_cols = ["No.", "Length", "Sequence Number"]
            for col in numeric_cols:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce")

            # Handle missing values
            df.fillna("No Data", inplace=True)

            return df
        else:
            print("No UDP packets extracted from the pcap file.")
            return None

    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        return None
