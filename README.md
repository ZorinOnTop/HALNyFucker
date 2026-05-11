# HALNyFucker 🔧

> Twój najlepszy port forwarder dla zbugowanych routerów HALNy — bo skoro router nie działa, ktoś musi to naprawić.

[![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.1-black?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![UPnP](https://img.shields.io/badge/UPnP-auto--managed-orange)](https://en.wikipedia.org/wiki/Universal_Plug_and_Play)

---

## Czyja to wina?

Chińskiego producenta oprogramowania dla routerów HALNy, który dostarczył firmware jakości godnej podziwu. Panel administracyjny działa jak działa, czyli w zasadzie nie działa. HALNyFucker istnieje wyłącznie dlatego, że ktoś gdzieś w Chinach uznał, że port forwarding to feature opcjonalny.

---

## Co to jest?

HALNyFucker to aplikacja webowa napisana w Pythonie (Flask), która działa jako **lokalny serwer WWW** na porcie `42569`.

Zarządzasz port forwardingiem przez przeglądarkę, a HALNyFucker ogarnia komunikację z routerem przez **UPnP SOAP** (`port 5555`) - bez klikania po zepsutym panelu administracyjnym.

---

## Jak to działa?

1. Po uruchomieniu HALNyFucker **automatycznie startuje monitor UPnP** w tle (osobny wątek).
2. Co 60 sekund sprawdzany jest stan UPnP przez HTTP request na `http://<router>:5555`.
3. Jeśli UPnP nie odpowiada, HALNyFucker **loguje się do routera** przez jego API (`/cgi-bin/check_auth.json`), wyłącza UPnP i włącza je z powrotem - wszystko automatycznie. Sprytnie oblicza nawet cookie `EBOOVALUE` jako CRC32 danych formularza, bo router tego wymaga.
4. Jednocześnie działa **sync portów** - co 60 sekund pobiera aktualne mappingi z UPnP i synchronizuje je z lokalną bazą danych (SQLite).
5. Opcjonalnie: jeśli włączysz "Dodaj automatycznie porty" w ustawieniach, brakujące porty z bazy są automatycznie przywracane do UPnP po każdej awarii.

---

## Funkcje

- **Automatyczne zarządzanie UPnP** - włącza się samo, monitoruje co 60s, restartuje przy awarii
- **Port forwarding przez UPnP SOAP** - dodawanie i usuwanie reguł TCP, UDP oraz TCP/UDP
- **Synchronizacja dwukierunkowa** - porty z UPnP trafiają do bazy, porty z bazy wracają do UPnP
- **Panel WWW z autoryzacją** - login + hasło hashowane Argon2, sesje do 30 dni, rate limiting (3 próby/min)
- **Instalator przy pierwszym uruchomieniu** - kreator konfiguruje login, hasło i dane routera
- **REST API** - zewnętrzne API (`/api/v1/`) z kluczem `X-API-Key` do zarządzania portami i UPnP
- **Powiadomienia** - Discord (webhook) i Telegram (bot) przy problemach z UPnP
- **Logi** - timestampowane, z poziomami INFO / WARNING / ERROR

---

## Porty

| Usługa | Port | Opis |
|---|---|---|
| Panel WWW | `42569` | HALNyFucker |
| UPnP (router) | `5555` | SOAP + health check |

---

## Wymagania

- Python 3.8+
- `curl` zainstalowany w systemie (używany przy restarcie UPnP)
- Router HALNy lub inny obsługujący UPnP na porcie 5555

---

## Instalacja

```bash
git clone https://github.com/ZorinOnTop/HALNyFucker.git
cd HALNyFucker
pip install -r requirements.txt
```

**Zależności:**
- `Flask==3.1.2`
- `argon2-cffi==23.1.0`
- `requests==2.31.0`
- `flask-limiter==3.5.1`

---

## Uruchomienie

### Zwykłe

```bash
python main.py
```

Wejdź na `http://localhost:42569` - przy pierwszym uruchomieniu zostaniesz przekierowany do **instalatora**, gdzie ustawisz login, hasło oraz dane logowania do routera.

### Jako usługa systemowa

**Linux (systemd):**

```bash
sudo cp halnyfucker.service /etc/systemd/system/
sudo systemctl enable halnyfucker
sudo systemctl start halnyfucker
```

**Windows (service):**

```bash
python main.py --install-service
```

---

## REST API

HALNyFucker udostępnia zewnętrzne API. Wygeneruj klucz w Ustawieniach, następnie dołącz go do każdego żądania jako header `X-API-Key`.

| Metoda | Endpoint | Opis |
|---|---|---|
| `GET` | `/api/v1/status` | Status systemu (uptime, UPnP, liczba portów) |
| `GET` | `/api/v1/ports` | Lista portów z bazy |
| `POST` | `/api/v1/ports` | Dodaj port (JSON body) |
| `DELETE` | `/api/v1/ports/<id>` | Usuń port |
| `GET` | `/api/v1/upnp/status` | Czy UPnP odpowiada |
| `GET` | `/api/v1/upnp/mappings` | Aktualne mappingi z routera (live) |
| `POST` | `/api/v1/upnp/restart` | Wymuś restart UPnP |
| `GET` | `/api/v1/settings` | Pobierz ustawienia |
| `PUT` | `/api/v1/settings` | Zaktualizuj ustawienie |

Pełna dokumentacja dostępna w panelu pod `/api-docs`.

---

## Często zadawane pytania

**Czy muszę ręcznie włączyć UPnP w routerze przed startem?**
Nie. HALNyFucker sam to ogarnia.

**Czy działa tylko z HALNy?**
Nie, działa z każdym routerem obsługującym UPnP na porcie 5555 i mającym API kompatybilne z HALNy. Nazwa jest "dedykowana" HALNy.

**Czy to legalne?**
Otwierasz porty na własnym routerze w swojej sieci. Jak najbardziej.

---

## Wkład w projekt

Pull requesty mile widziane. Jeśli masz router HALNy i natknąłeś się na kolejnego buga w firmware, otwórz issue.
