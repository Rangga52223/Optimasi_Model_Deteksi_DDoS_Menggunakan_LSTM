import pandas as pd
from scapy.all import sniff

# Daftar fitur yang akan digunakan untuk Machine Learning
columns = [
    'Timestamp', 'Destination Port', 'Bwd Packet Length Max',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Max Packet Length',
    'Min Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'Avg Bwd Segment Size', 'Average Packet Size'
]

# Buat DataFrame kosong untuk menyimpan hasil sniffing
df = pd.DataFrame(columns=columns)

# Fungsi untuk mengekstrak fitur dari paket
def extract_packet_features(packet):
    try:
        packet_length = len(packet)

        features = {
            'Timestamp': packet.time,  # Waktu paket diterima
            'Destination Port': packet.dport if hasattr(packet, 'dport') else 0,
            'Bwd Packet Length Max': packet_length,
            'Bwd Packet Length Mean': packet_length,  # Akan dihitung rata-rata nanti
            'Bwd Packet Length Std': 0,  # Placeholder (dihitung setelah cukup data)
            'Max Packet Length': packet_length,
            'Min Packet Length': packet_length,
            'Packet Length Mean': packet_length,
            'Packet Length Std': 0,  # Placeholder
            'Packet Length Variance': 0,  # Placeholder
            'Avg Bwd Segment Size': packet_length,
            'Average Packet Size': packet_length
        }
        return features

    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# Fungsi untuk menangkap paket dan menambahkan ke DataFrame
def packet_sniffer(packet):
    global df
    features = extract_packet_features(packet)

    if features:  # Hanya tambahkan jika fitur valid
        new_row = pd.DataFrame([features])
        df = pd.concat([df, new_row], ignore_index=True)

# Fungsi utama untuk sniffing
def main(interface):
    try:
        print(f"Sniffing on interface: {interface}")
        sniff(prn=packet_sniffer, iface=interface, count=1000)  # Tangkap 1000 paket

        # Hitung ulang nilai statistik
        if not df.empty:
            df['Bwd Packet Length Mean'] = df['Bwd Packet Length Max'].mean()
            df['Bwd Packet Length Std'] = df['Bwd Packet Length Max'].std()
            df['Packet Length Mean'] = df['Max Packet Length'].mean()
            df['Packet Length Std'] = df['Max Packet Length'].std()
            df['Packet Length Variance'] = df['Max Packet Length'].var()

        # Simpan ke CSV
        df.to_csv("packet_features.csv", index=False)
        print("Paket berhasil disimpan di packet_features.csv")

    except PermissionError:
        print("Error: Jalankan skrip ini sebagai Administrator!")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    interface = input("Masukkan nama network interface untuk sniffing: ")
    main(interface)