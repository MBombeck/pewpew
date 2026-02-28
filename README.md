# PewPew Attack Map

Echtzeit-Visualisierung von Netzwerkangriffen auf einer Weltkarte. Zeigt Fail2Ban-Events und UDM IDS/IPS-Threats als animierte Arcs von der Angreifer-Position nach Bochum.

![Dracula Theme](https://img.shields.io/badge/theme-dracula-bd93f9)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue)
![Flask](https://img.shields.io/badge/flask-3.1-green)

## Features

- **Fail2Ban-Integration**: Ban, Found, Restore Ban Events mit GeoIP-Koordinaten
- **UDM IDS/IPS**: Suricata Threat-Events von der UniFi Dream Machine Pro (nur eingehende Threats mit oeffentlichen IPs)
- **Dracula Theme**: Vollstaendiges Farbschema basierend auf der [Dracula](https://draculatheme.com/) Palette
- **Interaktive Karte**: D3.js + Datamaps mit animierten Arcs, Pulsing Target Marker, Hover-Tooltips
- **Live + History**: Live-Polling (10s) oder historische Ansicht (1h, 6h, 24h)
- **Sound**: Optionaler Pew-Sound bei Bans
- **GeoIP-Enrichment**: Automatische Koordinaten-Aufloesung fuer IDS-Events via ip-api.com

## Architektur

```
┌──────────────┐     Syslog/CEF      ┌────────┐     Loki Query     ┌────────────┐
│   UDM Pro    │ ──────────────────>  │  Loki  │ <───────────────── │  PewPew    │
│  (IDS/IPS)   │                      │        │                    │  Backend   │
└──────────────┘                      │        │                    │  (Flask)   │
                                      │        │                    └─────┬──────┘
┌──────────────┐     fail2ban-geo     │        │                          │
│  Fail2Ban    │ ──────────────────>  │        │                    ┌─────┴──────┐
│ (apps/ops)   │     (Cron 5min)      └────────┘                    │  Frontend  │
└──────────────┘                                                    │ (D3/Datamaps)
                                                                    └────────────┘
```

### Datenquellen

| Quelle | Loki Job | Format | Inhalt |
|--------|----------|--------|--------|
| Fail2Ban | `fail2ban_geo` | JSON | Ban/Found Events mit GeoIP (lat, lon, country, city, isp) |
| UDM IDS/IPS | `udm_pro` | CEF | Suricata Threat Detected Events (gefiltert: nur `incoming` + public IPs) |

### Farbschema (Dracula)

| Event | Farbe | CSS Variable |
|-------|-------|-------------|
| Ban | Pink `#ff79c6` | `--ban` |
| SSH Found | Cyan `#8be9fd` | `--sshd` |
| SSH Aggressive | Orange `#ffb86c` | `--aggressive` |
| Portscan | Gruen `#50fa7b` | `--portscan` |
| IDS High Risk | Rot `#ff5555` | `--ids-high` |
| IDS Alert | Gelb `#f1fa8c` | `--ids-alert` |

## Deployment

### Voraussetzungen

- Docker + Docker Compose
- Loki-Instanz mit `fail2ban_geo` und/oder `udm_pro` Job
- Traefik als Reverse Proxy (optional)

### Konfiguration

Umgebungsvariablen in `docker-compose.yml`:

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `LOKI_URL` | `http://loki:3100` | Loki API URL |
| `LOKI_USER` | _(leer)_ | Loki Basic Auth User |
| `LOKI_PASS` | _(leer)_ | Loki Basic Auth Passwort |
| `QUERY_INTERVAL` | `30` | Polling-Intervall in Sekunden |
| `QUERY_RANGE` | `1h` | Standard-Zeitfenster fuer Live-Modus |
| `TARGET_LAT` | `51.4818` | Ziel-Breitengrad (Bochum) |
| `TARGET_LON` | `7.2162` | Ziel-Laengengrad (Bochum) |

### Starten

```bash
docker compose up -d
```

Die App ist dann unter `http://localhost:8091` erreichbar.

## API

| Endpoint | Methode | Beschreibung |
|----------|---------|-------------|
| `/` | GET | Frontend (SPA) |
| `/api/attacks` | GET | Attack Events (optional `?range=1h\|6h\|24h`) |
| `/api/health` | GET | Health Check mit Cache-Alter und GeoIP-Cache-Groesse |

## Projektstruktur

```
pewpew/
├── server.py           # Flask Backend (Loki-Queries, CEF-Parser, GeoIP)
├── static/
│   ├── index.html      # Frontend SPA (D3.js, Datamaps, Dracula Theme)
│   └── favicon.svg     # Crosshair Favicon
├── Dockerfile          # Python 3.12-slim + Gunicorn
├── docker-compose.yml  # Container-Config mit Traefik-Labels
├── requirements.txt    # Python Dependencies
└── README.md
```
