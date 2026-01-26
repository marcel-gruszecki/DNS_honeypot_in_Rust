# DNS Honeypot Project

Asynchroniczny system typu honeypot przeznaczony do monitorowania i analizy ruchu DNS, napisany w języku Rust z wykorzystaniem bibliotek Tokio oraz SQLx. System symuluje działanie serwera DNS, rejestrując wszystkie przychodzące zapytania i poddając je automatycznej klasyfikacji pod kątem wzorców charakterystycznych dla cyberataków.

---

## Opis Systemu

Honeypot przechwytuje zapytania DNS przesyłane protokołami UDP oraz TCP. Dane są składowane w lokalnej bazie SQLite, która jest automatycznie inicjalizowana przy starcie aplikacji. System zawiera wbudowany silnik analityczny, który w określonych interwałach czasowych przetwarza surowe logi i generuje raporty bezpieczeństwa.

---

## Struktura Bazy Danych

Aplikacja zarządza dwiema głównymi tabelami. Poniżej znajduje się szczegółowy opis ich zawartości:

### Tabela: logs
Przechowuje surowe informacje o każdym przechwyconym zapytaniu DNS.

| Kolumna | Opis |
| :--- | :--- |
| **id** | Unikalny identyfikator wpisu (Primary Key). |
| **timestamp** | Dokładny czas zdarzenia z precyzją milisekundową. |
| **day** | Data zdarzenia w formacie YYYY-MM-DD (ułatwia agregację). |
| **question** | Treść zapytania DNS wysłanego przez klienta (nazwa domeny). |
| **question_length** | Długość zapytania wyrażona w liczbie znaków. |
| **response** | Odpowiedź wygenerowana przez serwer. |
| **server_ip** | Adres IP lokalnego interfejsu, na którym odebrano ruch. |
| **server_port** | Port lokalny, na którym nasłuchiwał serwer (domyślnie 53). |
| **client_ip** | Adres IP hosta inicjującego zapytanie. |
| **client_port** | Port źródłowy klienta. |
| **q_type** | Typ rekordu DNS (np. A, AAAA, TXT, ANY, AXFR). |

### Tabela: daily_summary
Przechowuje zagregowane wyniki analizy bezpieczeństwa.

| Kolumna | Opis |
| :--- | :--- |
| **day** | Dzień, którego dotyczy podsumowanie (klucz główny). |
| **by_class** | Nazwa sklasyfikowanej kategorii ataku (klucz główny). |
| **total_events** | Łączna liczba wykrytych incydentów danej klasy w ciągu dnia. |
| **first_seen** | Godzina wystąpienia pierwszego zdarzenia danej klasy. |
| **last_seen** | Godzina wystąpienia ostatniego zdarzenia danej klasy. |

---

## Klasyfikacja Ataków

Silnik analityczny automatycznie rozpoznaje i kategoryzuje następujące zagrożenia:

| Klasa ataku | Opis i kryteria detekcji |
| :--- | :--- |
| **Flood Attack** | Wykrywany przy intensywnym ruchu (powyżej 50 zapytań na minutę z jednego IP). |
| **Zone Transfer** | Próby pobrania strefy DNS (typy AXFR/IXFR) w celu rekonesansu sieci. |
| **DNS Tunneling** | Zapytania powyżej 60 znaków, co sugeruje ukryty kanał komunikacji. |
| **Amplification Attempt** | Wykorzystanie typów ANY lub TXT do ataków DDoS typu Reflection. |
| **Forbidden Domain** | Zapytania o domeny zdefiniowane w pliku `forbidden_domains.txt`. |

---

## Instrukcja Uruchomienia

### 1. Przygotowanie struktury plików
Przed uruchomieniem należy utworzyć katalog na dane oraz plik konfiguracyjny dla domen zabronionych:
```bash
mkdir -p data
touch data/forbidden_domains.txt
```
Uruchomienie:
```bash
sudo docker compose up -d --build
```
Usunięcie:
```bash
sudo docker compose down -v
```

### 2. Sprawdzanie logów
```
docker compose logs
```

### 3. Przegląd zebranych danych
Interfejs graficzny do zarządzania bazą danych i podglądu tabel jest dostępny bezpośrednio w przeglądarce. Domyślne hasło do interfejsu to haslo:
```
http://localhost:8080
```

### 4. Przykładowe testy
```bash
#!/bin/bash

TARGET="127.0.0.1"
PORT="53"

# 2. Zone Transfer (Próba pobrania strefy)
dig @$TARGET -p $PORT example.com AXFR
dig @$TARGET -p $PORT example.com IXFR

# 3. DNS Tunneling (Długie zapytanie > 60 znaków)
# LONG_QUERY="v1-a5b6c7d8e9f0g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v6w7x8y9z0-extra-long-subdomain.example.com"
# Łącznie ma ok. 80 znaków, ale każda część ma mniej niż 63.
dig @127.0.0.1 -p 8080 $LONG_QUERY A
# dig @$TARGET -p $PORT $LONG_QUERY A

# 4. Amplification Attempt (Typy ANY i TXT)
dig @$TARGET -p $PORT google.com ANY
dig @$TARGET -p $PORT google.com TXT

# 5. Forbidden Domain (Upewnij się, że domena jest w forbidden_domains.txt)
# Zakładamy, że dodałeś 'facebook.com' do pliku
dig @$TARGET -p $PORT zakazanadomena.com A

# 6. Flood Attack (Wysyłanie 60 zapytań w pętli - limit masz na 50)
for i in {1..60}
do
   dig @$TARGET -p $PORT flood-test-$i.com A +short > /dev/null 2>&1
done

```