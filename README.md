# PCAP Traffic Analyzer

**PCAP Traffic Analyzer** to program napisany w Pythonie, służący do analizy ruchu sieciowego zapisanych w plikach PCAP. Narzędzie klasyfikuje intencje użytkowników, analizuje charakterystykę przepływów i generuje statystyki ruchu w sieci. Projekt wspiera także rozwiązywanie nazw domen oraz klasyfikację na podstawie zakresów IP i portów.

## Funkcje programu

- **Analiza ruchu sieciowego:**
  - Identyfikacja intencji użytkowników na podstawie protokołów, portów i domen.
  - Klasyfikacja strumieni jako streaming na żywo, VoD, gry online i inne.
  - Wyodrębnianie przepływów na podstawie IP źródłowego, docelowego oraz protokołu.
  
- **Obsługa plików PCAP:**
  - Automatyczna analiza i eksport wyników do plików CSV.
  - Zbieranie statystyk, takich jak liczba pakietów, średnia i mediana odstępów czasowych między pakietami.

- **Rozwiązywanie nazw domen:**
  - Obsługa cache domenowego dla przyspieszenia analizy.
  - Możliwość wykluczenia lokalnych adresów IP oraz określonych zakresów.

- **Elastyczność:**
  - Wsparcie dla niestandardowych list słów kluczowych domen i zakresów IP.
  - Konfigurowalne parametry analizy, takie jak minimalny rozmiar pakietu.

## Wymagania

- Python 3.8 lub nowszy
- Biblioteki:
  - `pyshark`
  - `ipaddress`
  - `datetime`
  - `socket`
  - `json`
  - `csv`

## Instalacja

1. Sklonuj repozytorium:
   ```bash
   git clone https://github.com/alkus88/analizerPCAP.git
   cd analizerPCAP
   ```

2. Zainstaluj wymagane biblioteki:
   ```bash
   pip install -r pyshark
   ```

3. Przygotuj pliki konfiguracyjne:
   - **`domain_keywords.json`**: Słowa kluczowe do klasyfikacji domen.
   - **`streaming_services`**: Pliki zawierające zakresy IP dla serwisów streamingowych (np. Netflix, HBO).
   - **Plik PCAP**: Umieść swój plik PCAP w katalogu projektu.

## Użycie

1. Skonfiguruj plik wejściowy PCAP i inne parametry w kodzie:
   ```python
   pcap_file = "path/to/your.pcap"
   output_csv = "analyzed_traffic.csv"
   flows_csv = "flows.csv"
   ```

2. Uruchom program:
   ```bash
   python analyze_pcap_program.py
   ```

3. Wyniki zostaną zapisane w plikach:
   - **`analyzed_traffic.csv`**: Szczegółowe dane o pakietach.
   - **`flows.csv`**: Statystyki przepływów.

## Struktura katalogu

```plaintext
analizerPCAP/
│
├── analyze_pcap_program.py    # Główny kod programu
├── requirements.txt           # Lista wymaganych bibliotek
├── domain_keywords.json       # Słowa kluczowe do klasyfikacji domen
├── netflix_ips.txt            # Zakresy IP dla Netflix
├── prime_ips.txt              # Zakresy IP dla Prime
├── hbo_ips.txt                # Zakresy IP dla HBO GO
├── disney_ips.txt             # Zakresy IP dla Disney+
├── analyzed_traffic.csv       # Wyniki analizy
└── flows.csv                  # Statystyki przepływów
```

## Przykład działania

Fragment danych wyjściowych z **`analyzed_traffic.csv`**:

| Source IP      | Destination IP | Protocol | Source Port | Destination Port | Packet Length | Intention                                  |
|----------------|----------------|----------|-------------|------------------|---------------|--------------------------------------------|
| 192.168.1.100 | 8.8.8.8        | UDP      | 52345       | 53               | 78            | DNS -> Zapytanie domenowe -> Niska latencja |

## Plany rozwoju

- Dodanie wsparcia dla HTTP/2 i QUIC.
- Automatyczna klasyfikacja bardziej zaawansowanych typów ruchu.
- Integracja z bazami danych dla dużych zbiorów danych.

## Licencja

Projekt jest dostępny na licencji MIT. Szczegóły znajdują się w pliku `LICENSE`.

## Autorzy

Projekt rozwijany przez [alkus88](https://github.com/alkus88).
