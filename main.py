import pyshark
import csv
from ipaddress import ip_address, ip_network

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

# Funkcja klasyfikująca intencję na podstawie adresu IP i protokołu
def classify_intention(ip_src, ip_dst, protocol, streaming_services):
    if protocol == "UDP" or protocol == "TCP":
        for service, data in streaming_services.items():
            if ip_in_subnet(ip_src, data["subnets"]) or ip_in_subnet(ip_dst, data["subnets"]):
                return data["intention"]
    return "Inna intencja"

# Analiza pliku PCAP i generowanie wyników
def analyze_pcap(file_path, streaming_services, output_csv, max_entries=100000):
    cap = pyshark.FileCapture(file_path)
    results = []
    packet_count = 0

    for pkt in cap:
        try:
            packet_count += 1
            # Wyświetl licznik pakietów co 10 000 iteracji
            if packet_count % 10000 == 0:
                print(f"Przetworzono pakietów: {packet_count}")

            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            protocol = pkt.transport_layer

            # Klasyfikacja intencji
            intention = classify_intention(ip_src, ip_dst, protocol, streaming_services)

            # Dodajemy dane do wyników
            results.append({
                "Source IP": ip_src,
                "Destination IP": ip_dst,
                "Protocol": protocol,
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
youtube_file = "youtube_ips.txt"
output_csv = "analyzed_traffic.csv"

# Wczytanie zakresów IP
streaming_services = {
    "Netflix": {"subnets": load_ip_ranges(netflix_file), "intention": "Streaming wideo NetFlix -> Wysoka przepustowość burst"},
    "Disney+": {"subnets": load_ip_ranges(disney_file), "intention": "Streaming wideo Disney+ -> Wysoka przepustowość burst"},
    "HBO MAX": {"subnets": load_ip_ranges(hbo_file), "intention": "Streaming wideo HBO MAX -> Wysoka przepustowość burst"},
    "Prime Video": {"subnets": load_ip_ranges(prime_file), "intention": "Streaming wideo Prime Video -> Wysoka przepustowość burst"},
}

# Uruchomienie analizy
analyze_pcap(pcap_file, streaming_services, output_csv, max_entries=100000)
