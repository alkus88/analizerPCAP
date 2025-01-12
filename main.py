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


def analyze_flow(ip_src, ip_dst, protocol, timestamp, packet_size, min_packet_size=700):

    # Upewnij się, że timestamp jest obiektem datetime
    if not isinstance(timestamp, datetime):
        timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f")

    # Uproszczenie klucza przepływu (bez portów)
    flow_key = (ip_src, ip_dst, protocol)

    if flow_key not in flows:
        flows[flow_key] = {"timestamps": [], "packet_sizes": []}

        # Dodaj tylko pakiety spełniające kryterium wielkości
    if packet_size >= min_packet_size:
        flows[flow_key]["timestamps"].append(timestamp)
        flows[flow_key]["packet_sizes"].append(packet_size)

        # Logowanie przepływu
    print(f"Przepływ: {flow_key}, Liczba pakietów: {len(flows[flow_key]['timestamps'])}")

    # Klasyfikacja po 10 pakietach spełniających kryterium
    if len(flows[flow_key]["timestamps"]) >= 10:
        times = flows[flow_key]["timestamps"]

        # Obliczamy odstępy czasowe w sekundach
        deltas = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
        avg_delta = sum(deltas) / len(deltas)

        # Logowanie odstępów czasowych
        print(f"Przepływ: {flow_key}, Średni odstęp: {avg_delta}, Liczba pakietów: {len(times)}")

        # Klasyfikacja
        if avg_delta < 0.01:
            return "live"
        elif 0.01 <= avg_delta < 0.1:
            return "vod"
        else:
            return "inny_typ"
    else:
        # Za mało danych do klasyfikacji
        return None


def classify_by_packet_length(packet_length):
    if packet_length is None:
        return "Nieznana długość pakietu"
    if packet_length >= 1000:
        return "Duży pakiet -> Wysoka przepustowość"
    elif packet_length < 100:
        return "Mały pakiet -> Niska przepustowość"
    else:
        return "Średni pakiet -> Średnia przepustowość"


# Funkcja do klasyfikacji gier online na podstawie portów
def classify_game_intention(src_port, dst_port, game_ports):
    try:
        for game, ports in game_ports.items():
            for port in ports:
                # Sprawdź, czy port to zakres
                if isinstance(port, tuple) and len(port) == 2:
                    if port[0] <= src_port <= port[1] and port[0] <= dst_port <= port[1]:
                        # print(f"Rozpoznano grę: {game} dla portów: src_port={src_port}, dst_port={dst_port}")
                        return f"Gra online -> {game} -> Wysoka responsywność"
                # Sprawdź, czy port to pojedyncza wartość
                elif isinstance(port, int):
                    if src_port == port or dst_port == port:
                        # print(f"Rozpoznano grę: {game} dla portów: src_port={src_port}, dst_port={dst_port}")
                        return f"Gra online -> {game} -> Wysoka responsywność"
        # print(f"Nie rozpoznano gry: src_port={src_port}, dst_port={dst_port}")
        return None
    except Exception as e:
        print(f"Błąd w klasyfikacji gry: {e}")
        return None

# Funkcja klasyfikująca intencję na podstawie adresu IP i protokołu


def classify_intention(ip_src,
                       ip_dst,
                       protocol,
                       streaming_services,
                       game_ports,
                       timestamp,
                       src_port,
                       dst_port,
                       packet_length):
    # Rozpoznaj gry online najpierw
    game_intention = classify_game_intention(src_port, dst_port, game_ports)
    if game_intention:
        return game_intention

    # Rozpoznaj ruch DNS
    if protocol == "UDP" and (src_port == 53 or dst_port == 53):
        return "DNS -> Zapytanie domenowe -> Niska przepustowość, niska latencja"

    # Rozpoznaj ruch VoIP (SIP i RTP)
    if protocol in ["UDP", "TCP"]:
        # SIP
        if src_port in [5060, 6050] or dst_port in [5060, 6050]:
            return "VoIP -> SIP -> Niska przepustowość, niska latencja"
        # RTP
        if 16384 <= src_port <= 32767 and 16384 <= dst_port <= 32767:
            return "VoIP -> RTP -> Niska przepustowość, niska latencja"

    # Następnie rozpoznaj serwisy streamingowe
    chosen_service = None
    for service, data in streaming_services.items():
        if ip_in_subnet(ip_src, data["subnets"]) or ip_in_subnet(ip_dst, data["subnets"]):
            chosen_service = service
            break

    if chosen_service:
        # Jeśli serwis został rozpoznany, wykonaj dodatkową analizę typu streamingu
        streaming_type = analyze_flow(ip_src, ip_dst, protocol, timestamp, packet_length)
        if streaming_type == "live":
            return f"{chosen_service} -> Streaming na żywo -> Wysoka przepustowość"
        elif streaming_type == "vod":
            return f"{chosen_service} -> VoD -> Wysoka przepustowość"
        else:
            return f"{chosen_service} -> Nieokreślony typ streamingu"

    streaming_type = analyze_flow(ip_src, ip_dst, protocol, timestamp, packet_length)
    if streaming_type:
        if streaming_type == "live":
            return "Streaming na żywo -> Wysoka przepustowość"
        elif streaming_type == "vod":
            return "VoD -> Wysoka przepustowość"

    # Jeśli nic nie pasuje, zwróć "Inna intencja"
    return "Inna intencja"

# Analiza pliku PCAP i generowanie wyników


def analyze_pcap(file_path, streaming_services, game_ports, output_csv, flows_csv, max_entries=100000):

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

            # Pobranie portów źródłowego i docelowego
            src_port = int(pkt[protocol].srcport) if hasattr(pkt[protocol], "srcport") else None
            dst_port = int(pkt[protocol].dstport) if hasattr(pkt[protocol], "dstport") else None

            # Pobranie długości pakietu
            packet_length = int(pkt.length) if hasattr(pkt, "length") else None

            # Klasyfikacja intencji
            intention = classify_intention(
                ip_src, ip_dst, protocol, streaming_services, game_ports, timestamp, src_port, dst_port, packet_length
            )

            # Klasyfikacja na podstawie długości pakietu
            packet_size_classification = classify_by_packet_length(packet_length)
            if intention:
                intention = f"{intention} ({packet_size_classification})"
            else:
                intention = packet_size_classification

            # Dodajemy dane do wyników
            results.append({
                "Source IP": ip_src,
                "Destination IP": ip_dst,
                "Protocol": protocol,
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Packet Length": packet_length,
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
        fieldnames = ["Source IP",
                      "Destination IP",
                      "Protocol",
                      "Source Port",
                      "Destination Port",
                      "Packet Length",
                      "Timestamp",
                      "Intention"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"Wyniki zapisano w pliku: {output_csv}")

    # Zapis przepływów do pliku CSV
    with open(flows_csv, mode='w', newline='') as csvfile:
        fieldnames = ["Flow Key", "Packet Count", "Timestamps", "Packet Sizes", "Avg Packet Size", "Avg Delta"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for flow_key, flow_data in flows.items():
            timestamps = flow_data["timestamps"]
            packet_sizes = flow_data["packet_sizes"]

            # Oblicz średni odstęp czasowy (jeśli istnieje więcej niż jeden timestamp)
            if len(timestamps) > 1:
                deltas = [(timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)]
                avg_delta = sum(deltas) / len(deltas)
            else:
                avg_delta = None

            # Oblicz średni rozmiar pakietu (jeśli istnieją dane o rozmiarach pakietów)
            avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else None

            # Zapisz dane przepływu do pliku
            writer.writerow({
                "Flow Key": flow_key,
                "Packet Count": len(timestamps),
                "Timestamps": [str(ts) for ts in timestamps],
                "Packet Sizes": packet_sizes,
                "Avg Packet Size": avg_packet_size,
                "Avg Delta": avg_delta,
            })

    print(f"Przepływy zapisano w pliku: {flows_csv}")


# Ścieżki do plików
pcap_file = ("C:/Users/Gryngiel/Documents/Studia 2st/"
             "Profilowanie użytkowników/Program do analizy/"
             "AnalizaPCAP/DANE/traffic_2024-12-02_15%3A03%3A19.pcap")
netflix_file = "netflix_ips.txt"
disney_file = "disney_ips.txt"
hbo_file = "hbo_ips.txt"
prime_file = "prime_ips.txt"
# youtube_file = "youtube_ips.txt"
output_csv = "analyzed_traffic.csv"
flows_csv = "flows.csv"

# Wczytanie zakresów IP
streaming_services = {
    "Netflix": {"subnets": load_ip_ranges(netflix_file),
                "intention": "Streaming wideo NetFlix -> Wysoka przepustowość burst"},
    "Disney+": {"subnets": load_ip_ranges(disney_file),
                "intention": "Streaming wideo Disney+ -> Wysoka przepustowość burst"},
    "HBO MAX": {"subnets": load_ip_ranges(hbo_file),
                "intention": "Streaming wideo HBO MAX -> Wysoka przepustowość burst"},
    "Prime Video": {"subnets": load_ip_ranges(prime_file),
                    "intention": "Streaming wideo Prime Video -> Wysoka przepustowość burst"},
    # "YouTube": {"subnets": load_ip_ranges(youtube_file),
    #    "intention": "Streaming wideo YouTube -> Wysoka przepustowość burst"},
}

# Słownik portów dla gier online
game_ports = {
    "Fortnite": [5222, 5795, 5800, 6515],
    "League of Legends": [5000, 8393, 8394, 5223],
    "Counter-Strike: GO": [27015, 27036],
    "Apex Legends": [4000, 4010, 4020, 4030],
    "Valorant": [7000, 7001, 7002, 7003],
    "Roblox": [(49152, 65535)],
}

# classify_game_intention(62188, 12345, game_ports)

# Uruchomienie analizy
analyze_pcap(pcap_file, streaming_services, game_ports, output_csv, flows_csv, max_entries=100000)
