# mini-tls

Projekt implementujący uproszczony protokół szyfrowany (mini TLS) w architekturze klient-serwer.

## Struktura

- `client/`: Kod klienta
- `server/`: Kod serwera
- `Dockerfile`: Konfiguracja obrazu Docker
- `docker-compose.yml`: Konfiguracja środowiska uruchomieniowego

## Wymagania
- Docker & Docker Compose


## Uruchomienie (Ręczne)

Aby uruchomić środowisko w sieci dockerowej:

1. Zbuduj i uruchom kontenery:
   ```bash
   docker-compose up --build
   ```

2. Aby wejść w interakcję z klientem lub serwerem, należy podłączyć się do kontenera.
   Ponieważ `docker-compose up` wyświetla logi, najlepiej uruchomić usługi w tle (`-d`) lub użyć osobnych terminali do obsługi wejścia.

   Zalecany sposób interakcji:

   **Serwer:**
   ```bash
   docker attach minitls-server
   ```
   (Aby odłączyć się bez zatrzymywania: `Ctrl+P`, `Ctrl+Q`)

   **Klient:**
   Znajdź ID lub nazwę kontenera klienta (np. `mini-tls-client-1`) i podłącz się:
   ```bash
   docker attach mini-tls-client-1
   ```

## Uruchomienie (Automatyczne - Linux)

Skrypt `start.sh` uruchamia środowisko w Dockerze, skaluje liczbę klientów i otwiera dla każdego osobne okno terminala.

1. Nadaj uprawnienia (jednorazowo):
   ```bash
   chmod +x start.sh
   ```

2. Uruchom skrypt podając liczbę klientów oraz limit serwera:
   ```bash
   ./start.sh 3 5
   ```
   (Uruchomi 3 klientów, serwer przyjmie max 5).

## Analiza Wireshark

Aby zobaczyć zaszyfrowaną komunikację:

1. **Rozpocznij nagrywanie:**
   W nowym oknie terminala uruchom:
   ```bash
   docker exec -it minitls-server tcpdump -i eth0 -w /captures/traffic.pcap
   ```

2. **Wygeneruj ruch:**
   W otwartych oknach klientów wykonaj komendy `connect`, `send hello`, itp.

3. **Zakończ nagrywanie:**
   Wciśnij `Ctrl+C` w oknie z `tcpdump`.

4. **Otwórz w Wireshark:**
   Plik `captures/traffic.pcap` pojawi się w folderze projektu. Otwórz go w Wiresharku.

5. **Odszyfrowanie:**
   Klucze sesji są automatycznie zapisywane w folderze `captures/`:
   - `server_secrets.log`
   - `client_secrets.log`

## Obsługa

### Klient
Dostępne komendy:
- `connect`: Nawiązuje połączenie z serwerem i wykonuje handshake.
```py
# Domyślne parametry
> connect

# Własne parametry P i G
> connect 2147483647 16807
```
- `send <wiadomość>`: Wysyła szyfrowaną wiadomość.
- `end`: Kończy sesję (wysyła EndSession) i wymusza ponowny handshake.
- `quit`: Zamyka aplikację.

### Serwer
Dostępne komendy:
- `list`: Wyświetla listę podłączonych klientów.
- `kill <ip> <port>`: Zrywa połączenie z wybranym klientem.

## Protokół

Zaimplementowano wariant **W1**: Encrypt-then-MAC.
- Wymiana kluczy: Diffie-Hellman.
- Szyfrowanie: XOR (symulacja OTP).
- Integralność: HMAC-SHA256.
