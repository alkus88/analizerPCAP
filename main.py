import pyshark
import csv
from ipaddress import ip_address, ip_network
from datetime import datetime

# Funkcja do wczytywania zakresów IP z pliku
def load_ip_ranges(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

# Funkcja sprawdzająca, czy adres IP należy do zakresu
def ip_in_subnet(ip, subnets):
    try:
        ip_obj = ip_address(ip)
        for subnet in subnets:
            if ip_obj in ip_network(subnet):
                return True
    except ValueError:
        print(f"Błędny adres IP: {ip}")
    return False

flows = {}

def analyze_flow(ip_src, ip_dst, protocol, timestamp):
    flow_key = (ip_src, ip_dst, protocol)
    if flow_key not in flows:
        flows[flow_key] = []
    flows[flow_key].append(timestamp)

    # Klasyfikacja po 20 pakietach
    if len(flows[flow_key]) >= 20:
        times = flows[flow_key]
        # Obliczamy odstępy czasowe w sekundach
        deltas = []
        for i in range(len(times)-1):
            delta = (times[i+1] - times[i]).total_seconds()
            deltas.append(delta)
        avg_delta = sum(deltas) / len(deltas)

        # Klasyfikacja
        if avg_delta < 4:
            return "live"
        elif avg_delta >= 6:
            return "vod"
        else:
            return "unknown"
    else:
        # Za mało danych do klasyfikacji
        return None

# Funkcja klasyfikująca intencję na podstawie adresu IP i protokołu
def classify_intention(ip_src, ip_dst, protocol, streaming_services, timestamp):
    # Najpierw rozpoznaj serwis
    chosen_service = None
    for service, data in streaming_services.items():
        if ip_in_subnet(ip_src, data["subnets"]) or ip_in_subnet(ip_dst, data["subnets"]):
            chosen_service = service
            break

    if chosen_service is None:
        return "Inna intencja"

    # Analiza flow w celu sprawdzenia typu streamingu
    streaming_type = analyze_flow(ip_src, ip_dst, protocol, timestamp)

    # Jeśli już znamy typ streamingu
    if streaming_type == "live":
        return f"{chosen_service} -> Streaming na żywo -> Wysoka przepustowość"
    elif streaming_type == "vod":
        return f"{chosen_service} -> VoD -> Wysoka przepustowość"
    else:
        # Jeszcze nie wiemy, albo nie do końca pewne
        return f"{chosen_service} -> (określanie typu...) -> Wysoka przepustowość"

# Analiza pliku PCAP i generowanie wyników
def analyze_pcap(file_path, streaming_services, output_csv, max_entries=100000):
    cap = pyshark.FileCapture(file_path)
    results = []
    packet_count = 0

    for pkt in cap:
        try:
            packet_count += 1
            # Wyświetl licznik pakietów co 10 000 iteracji
            if packet_count % 1000 == 0:
                print(f"Przetworzono pakietów: {packet_count}")

            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            protocol = pkt.transport_layer
            timestamp = pkt.sniff_time

            # Klasyfikacja intencji
            intention = classify_intention(ip_src, ip_dst, protocol, streaming_services, timestamp)

            # Dodajemy dane do wyników
            results.append({
                "Source IP": ip_src,
                "Destination IP": ip_dst,
                "Protocol": protocol,
                "Timestamp": timestamp,
                "Intention": intention,
            })

            # Zatrzymaj analizę po osiągnięciu limitu wpisów
            if len(results) >= max_entries:
                print(f"Osiągnięto limit {max_entries} wpisów. Zatrzymanie analizy.")
                break

        except AttributeError:
            print(f"Ignorowany pakiet: brak warstwy IP/transportowej (pakiet {packet_count})")
            continue
        except ValueError as e:
            print(f"Błąd podczas przetwarzania pakietu {packet_count}: {e}")
            continue

    cap.close()

    # Zapis wyników do pliku CSV
    with open(output_csv, mode='w', newline='') as csvfile:
        fieldnames = ["Source IP", "Destination IP", "Protocol", "Intention"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Wyniki zapisano w pliku: {output_csv}")

# Ścieżki do plików
pcap_file = "C:/Users/Gryngiel/Documents/Studia 2st/Profilowanie użytkowników/Program do analizy/AnalizaPCAP/DANE/traffic_2024-12-02_15%3A03%3A19.pcap"
netflix_file = "netflix_ips.txt"
disney_file = "disney_ips.txt"
hbo_file = "hbo_ips.txt"
prime_file = "prime_ips.txt"
#youtube_file = "youtube_ips.txt"
output_csv = "analyzed_traffic.csv"

# Wczytanie zakresów IP
streaming_services = {
    "Netflix": {"subnets": load_ip_ranges(netflix_file), "intention": "Streaming wideo NetFlix -> Wysoka przepustowość burst"},
    "Disney+": {"subnets": load_ip_ranges(disney_file), "intention": "Streaming wideo Disney+ -> Wysoka przepustowość burst"},
    "HBO MAX": {"subnets": load_ip_ranges(hbo_file), "intention": "Streaming wideo HBO MAX -> Wysoka przepustowość burst"},
    "Prime Video": {"subnets": load_ip_ranges(prime_file), "intention": "Streaming wideo Prime Video -> Wysoka przepustowość burst"},
#    "YouTube": {"subnets": load_ip_ranges(youtube_file), "intention": "Streaming wideo YouTube -> Wysoka przepustowość burst"},
}

# Uruchomienie analizy
analyze_pcap(pcap_file, streaming_services, output_csv, max_entries=100000)
