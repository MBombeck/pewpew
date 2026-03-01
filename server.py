#!/usr/bin/env python3
"""Attack Map backend — queries Loki for fail2ban ban events, UDM IDS alerts, and Cloudflare WAF events."""
import ipaddress
import json
import os
import re
import time
import threading
import urllib.request
from datetime import datetime, timezone, timedelta

import requests
from flask import Flask, jsonify, request, send_from_directory, make_response

app = Flask(__name__, static_folder="static")


@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100")
LOKI_USER = os.environ.get("LOKI_USER", "")
LOKI_PASS = os.environ.get("LOKI_PASS", "")
QUERY_INTERVAL = int(os.environ.get("QUERY_INTERVAL", "30"))
QUERY_RANGE = os.environ.get("QUERY_RANGE", "1h")
# Cloudflare GraphQL Analytics API
CF_API_EMAIL = os.environ.get("CF_API_EMAIL", "")
CF_API_KEY = os.environ.get("CF_API_KEY", "")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "")
# Own IPs to filter from CF events (monitoring, VPN exits, servers)
CF_OWN_IPS = set(os.environ.get("CF_OWN_IPS", "46.225.76.2,78.47.241.164,159.69.23.98").split(","))
# Uberspace real-IP attack log API
UBERSPACE_API_URL = os.environ.get("UBERSPACE_API_URL", "")
UBERSPACE_API_KEY = os.environ.get("UBERSPACE_API_KEY", "")
# Bochum coordinates (target for all arcs)
TARGET_LAT = float(os.environ.get("TARGET_LAT", "51.4818"))
TARGET_LON = float(os.environ.get("TARGET_LON", "7.2162"))

_cache = {"attacks": [], "last_update": 0, "total_bans": 0}
_lock = threading.Lock()

# GeoIP cache (in-memory, survives across poll cycles)
_geoip_cache = {}
_geoip_lock = threading.Lock()

VALID_RANGES = {"1h", "6h", "24h"}

# CEF extension key=value parser (handles values with spaces before next key=)
CEF_EXT_RE = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)")


def is_public_ip(ip_str):
    """Check if an IP address is public (not private/reserved)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False


def parse_cef(line):
    """Parse a CEF-formatted log line into a dict of extension fields."""
    if not line.startswith("CEF:"):
        return None
    # Split header: CEF:version|vendor|product|version|event_id|name|severity|extensions
    parts = line.split("|", 7)
    if len(parts) < 8:
        return None
    result = {
        "cef_vendor": parts[1],
        "cef_product": parts[2],
        "cef_event_id": parts[4],
        "cef_name": parts[5],
        "cef_severity": parts[6],
    }
    ext_str = parts[7]
    for m in CEF_EXT_RE.finditer(ext_str):
        result[m.group(1)] = m.group(2).strip()
    return result


def geoip_batch(ips):
    """Lookup GeoIP data for a batch of IPs using ip-api.com."""
    with _geoip_lock:
        new_ips = [ip for ip in ips if ip not in _geoip_cache]

    if not new_ips:
        with _geoip_lock:
            return {ip: _geoip_cache[ip] for ip in ips if ip in _geoip_cache}

    for i in range(0, len(new_ips), 100):
        batch = new_ips[i:i + 100]
        body = json.dumps(
            [{"query": ip, "fields": "status,country,countryCode,city,isp,lat,lon"} for ip in batch]
        ).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch", data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            results = json.loads(resp.read())
            with _geoip_lock:
                for ip, r in zip(batch, results):
                    if r.get("status") == "success":
                        _geoip_cache[ip] = {
                            "country": r["country"].replace("The Netherlands", "Netherlands"),
                            "cc": r["countryCode"],
                            "city": r.get("city", ""),
                            "isp": r.get("isp", ""),
                            "lat": r.get("lat", 0),
                            "lon": r.get("lon", 0),
                        }
                    else:
                        _geoip_cache[ip] = {
                            "country": "Unknown", "cc": "??",
                            "city": "", "isp": "",
                            "lat": 0, "lon": 0,
                        }
            if i + 100 < len(new_ips):
                time.sleep(2)  # ip-api.com rate limit
        except Exception as e:
            app.logger.error(f"GeoIP batch lookup failed: {e}")

    with _geoip_lock:
        return {ip: _geoip_cache[ip] for ip in ips if ip in _geoip_cache}


def query_loki_f2b(since=None):
    """Fetch recent fail2ban ban events from Loki."""
    query = '{job="fail2ban_geo"} | json | action!="Unban"'
    use_range = since if since in VALID_RANGES else QUERY_RANGE
    limit = 200 if use_range == "1h" else 500 if use_range == "6h" else 1000
    params = {
        "query": query,
        "limit": limit,
        "since": use_range,
    }
    auth = None
    if LOKI_USER and LOKI_PASS:
        auth = (LOKI_USER, LOKI_PASS)

    try:
        resp = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            auth=auth,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.error(f"Loki fail2ban query failed: {e}")
        return []

    attacks = []
    results = data.get("data", {}).get("result", [])
    for stream in results:
        labels = stream.get("stream", {})
        for ts_ns, line in stream.get("values", []):
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            lat = ev.get("lat", 0)
            lon = ev.get("lon", 0)
            if lat == 0 and lon == 0:
                continue

            # Loki timestamp in nanoseconds -> milliseconds for JS Date
            ts_ms = int(ts_ns) // 1000000
            attacks.append({
                "ts": ev.get("ts", ""),
                "ts_epoch": ts_ms,
                "ip": ev.get("ip", ""),
                "jail": ev.get("jail", ""),
                "action": ev.get("action", ""),
                "country": ev.get("country", "Unknown"),
                "cc": ev.get("cc", "??"),
                "city": ev.get("city", ""),
                "isp": ev.get("isp", ""),
                "host": labels.get("host", ""),
                "src_lat": lat,
                "src_lon": lon,
                "dst_lat": TARGET_LAT,
                "dst_lon": TARGET_LON,
                "source": "fail2ban",
            })

    return attacks


def query_loki_crowdsec(since=None):
    """Fetch recent CrowdSec ban events from Loki (GeoIP-enriched by crowdsec-geoip-log.sh)."""
    query = '{job="crowdsec_geo"} | json'
    use_range = since if since in VALID_RANGES else QUERY_RANGE
    limit = 200 if use_range == "1h" else 500 if use_range == "6h" else 1000
    params = {
        "query": query,
        "limit": limit,
        "since": use_range,
    }
    auth = None
    if LOKI_USER and LOKI_PASS:
        auth = (LOKI_USER, LOKI_PASS)

    try:
        resp = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            auth=auth,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.error(f"Loki CrowdSec query failed: {e}")
        return []

    attacks = []
    results = data.get("data", {}).get("result", [])
    for stream in results:
        labels = stream.get("stream", {})
        for ts_ns, line in stream.get("values", []):
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            lat = ev.get("lat", 0)
            lon = ev.get("lon", 0)
            if lat == 0 and lon == 0:
                continue

            ts_ms = int(ts_ns) // 1000000
            attacks.append({
                "ts": ev.get("timestamp", ""),
                "ts_epoch": ts_ms,
                "ip": ev.get("ip", ""),
                "jail": ev.get("jail", "crowdsec"),
                "action": ev.get("action", "Ban"),
                "country": ev.get("country", "Unknown"),
                "cc": ev.get("country_code", "??"),
                "city": ev.get("city", ""),
                "isp": ev.get("isp", ""),
                "host": labels.get("host", ev.get("host", "")),
                "src_lat": lat,
                "src_lon": lon,
                "dst_lat": TARGET_LAT,
                "dst_lon": TARGET_LON,
                "source": "crowdsec",
                "scenario": ev.get("scenario", ""),
            })

    return attacks


def query_loki_ids(since=None):
    """Fetch recent UDM IDS/IPS threat events from Loki."""
    query = '{job="udm_pro"} |~ "Threat Detected"'
    use_range = since if since in VALID_RANGES else QUERY_RANGE
    limit = 200 if use_range == "1h" else 500 if use_range == "6h" else 1000
    params = {
        "query": query,
        "limit": limit,
        "since": use_range,
    }
    auth = None
    if LOKI_USER and LOKI_PASS:
        auth = (LOKI_USER, LOKI_PASS)

    try:
        resp = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            auth=auth,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.error(f"Loki IDS query failed: {e}")
        return []

    # Collect all external source IPs for batch GeoIP
    raw_events = []
    ips_to_lookup = set()

    results = data.get("data", {}).get("result", [])
    for stream in results:
        for ts_ns, line in stream.get("values", []):
            cef = parse_cef(line)
            if not cef:
                continue

            # Only incoming threats (external attackers)
            direction = cef.get("UNIFIdirection", "")
            if direction != "incoming":
                continue

            src_ip = cef.get("src", "")
            if not src_ip or not is_public_ip(src_ip):
                continue

            cef["_ts_ns"] = ts_ns
            raw_events.append(cef)
            ips_to_lookup.add(src_ip)

    if not raw_events:
        return []

    # Batch GeoIP lookup
    geo_results = geoip_batch(list(ips_to_lookup))

    attacks = []
    for cef in raw_events:
        src_ip = cef.get("src", "")
        geo = geo_results.get(src_ip, {})
        lat = geo.get("lat", 0)
        lon = geo.get("lon", 0)
        if lat == 0 and lon == 0:
            continue

        # Map policy name to a jail-like category
        policy = cef.get("UNIFIpolicyName", "IDS")
        risk = cef.get("UNIFIrisk", "medium")
        signature = cef.get("UNIFIipsSignature", "")
        utc_time = cef.get("UNIFIutcTime", "")
        dst_port = cef.get("dpt", "")
        proto = cef.get("proto", "")

        # Determine action label based on risk level
        if risk == "high":
            action = "IDS High"
        else:
            action = "IDS Alert"

        ts_ms = int(cef.get("_ts_ns", "0")) // 1000000
        attacks.append({
            "ts": utc_time.replace("T", " ").replace("Z", "") if utc_time else "",
            "ts_epoch": ts_ms,
            "ip": src_ip,
            "jail": policy,
            "action": action,
            "country": geo.get("country", "Unknown"),
            "cc": geo.get("cc", cef.get("UNIFIsrcRegion", "??")),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", ""),
            "host": "UDMP",
            "src_lat": lat,
            "src_lon": lon,
            "dst_lat": TARGET_LAT,
            "dst_lon": TARGET_LON,
            "source": "ids",
            "signature": signature,
            "dst_port": dst_port,
            "proto": proto,
        })

    return attacks


def query_cloudflare(since=None):
    """Fetch recent Cloudflare WAF block events via GraphQL Analytics API."""
    if not CF_API_EMAIL or not CF_API_KEY or not CF_ZONE_ID:
        return []

    use_range = since if since in VALID_RANGES else QUERY_RANGE
    # CF free plan: max 86400s strict (not <=), so use 23h55m for "24h"
    range_minutes = {"1h": 60, "6h": 360, "24h": 1435}
    minutes = range_minutes.get(use_range, 60)
    dt_since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    limit = 200 if minutes <= 60 else 500 if minutes <= 360 else 1000

    query = """{
  viewer {
    zones(filter: {zoneTag: "%s"}) {
      firewallEventsAdaptive(
        filter: {
          datetime_gt: "%s",
          action_in: ["block", "managed_challenge", "js_challenge", "challenge", "drop"]
        },
        limit: %d,
        orderBy: [datetime_DESC]
      ) {
        action
        clientIP
        clientCountryName
        clientRequestHTTPHost
        clientRequestPath
        datetime
        source
      }
    }
  }
}""" % (CF_ZONE_ID, dt_since, limit)

    try:
        resp = requests.post(
            "https://api.cloudflare.com/client/v4/graphql",
            json={"query": query},
            headers={
                "X-Auth-Email": CF_API_EMAIL,
                "X-Auth-Key": CF_API_KEY,
                "Content-Type": "application/json",
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.error(f"Cloudflare GraphQL query failed: {e}")
        return []

    viewer = (data.get("data") or {}).get("viewer") or {}
    zones = viewer.get("zones", [])
    if not zones:
        errors = data.get("errors", [])
        if errors:
            app.logger.error(f"Cloudflare GraphQL errors: {errors}")
        return []

    events = zones[0].get("firewallEventsAdaptive", [])
    if not events:
        return []

    # Collect IPs for batch GeoIP (CF only gives country name, not coords)
    ips_to_lookup = set()
    filtered_events = []
    for ev in events:
        ip = ev.get("clientIP", "")
        if not ip or ip in CF_OWN_IPS or not is_public_ip(ip):
            continue
        filtered_events.append(ev)
        ips_to_lookup.add(ip)

    if not filtered_events:
        return []

    geo_results = geoip_batch(list(ips_to_lookup))

    attacks = []
    for ev in filtered_events:
        ip = ev.get("clientIP", "")
        geo = geo_results.get(ip, {})
        lat = geo.get("lat", 0)
        lon = geo.get("lon", 0)
        if lat == 0 and lon == 0:
            continue

        # Parse CF datetime to epoch ms
        dt_str = ev.get("datetime", "")
        try:
            dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
            ts_ms = int(dt.timestamp() * 1000)
        except (ValueError, AttributeError):
            ts_ms = 0

        action = ev.get("action", "block").replace("_", " ").title()
        cf_source = ev.get("source", "unknown")
        host = ev.get("clientRequestHTTPHost", "")
        path = ev.get("clientRequestPath", "")

        attacks.append({
            "ts": dt_str.replace("T", " ").replace("Z", "") if dt_str else "",
            "ts_epoch": ts_ms,
            "ip": ip,
            "jail": cf_source,
            "action": action,
            "country": geo.get("country", ev.get("clientCountryName", "Unknown")),
            "cc": geo.get("cc", "??"),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", ""),
            "host": host,
            "src_lat": lat,
            "src_lon": lon,
            "dst_lat": TARGET_LAT,
            "dst_lon": TARGET_LON,
            "source": "cloudflare",
            "path": path,
        })

    return attacks


def query_uberspace(since=None):
    """Fetch recent web scan/attack events from Uberspace real-IP log API."""
    if not UBERSPACE_API_URL or not UBERSPACE_API_KEY:
        return []

    use_range = since if since in VALID_RANGES else QUERY_RANGE
    range_minutes = {"1h": 60, "6h": 360, "24h": 1440}
    minutes = range_minutes.get(use_range, 60)

    try:
        resp = requests.get(
            UBERSPACE_API_URL,
            params={"since": minutes, "key": UBERSPACE_API_KEY},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        app.logger.error(f"Uberspace API query failed: {e}")
        return []

    events = data.get("attacks", [])
    if not events:
        return []

    # Collect IPs for batch GeoIP
    ips_to_lookup = {ev["ip"] for ev in events if ev.get("ip") and is_public_ip(ev["ip"])}
    if not ips_to_lookup:
        return []

    geo_results = geoip_batch(list(ips_to_lookup))

    attacks = []
    for ev in events:
        ip = ev.get("ip", "")
        if not ip or not is_public_ip(ip):
            continue
        geo = geo_results.get(ip, {})
        lat = geo.get("lat", 0)
        lon = geo.get("lon", 0)
        if lat == 0 and lon == 0:
            continue

        # Parse timestamp to epoch ms
        ts_str = ev.get("ts", "")
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            ts_ms = int(dt.timestamp() * 1000)
        except (ValueError, AttributeError):
            ts_ms = 0

        action = ev.get("action", "Web Scan")
        host = ev.get("host", "")
        path = ev.get("path", "")

        attacks.append({
            "ts": ts_str.replace("T", " ").replace("Z", "") if ts_str else "",
            "ts_epoch": ts_ms,
            "ip": ip,
            "jail": host.split(".")[0] if host else "uberspace",
            "action": action,
            "country": geo.get("country", "Unknown"),
            "cc": geo.get("cc", "??"),
            "city": geo.get("city", ""),
            "isp": geo.get("isp", ""),
            "host": host,
            "src_lat": lat,
            "src_lon": lon,
            "dst_lat": TARGET_LAT,
            "dst_lon": TARGET_LON,
            "source": "uberspace",
            "path": path,
        })

    return attacks


def query_all(since=None):
    """Fetch fail2ban, CrowdSec, IDS, Cloudflare, and Uberspace events, merge and sort."""
    f2b = query_loki_f2b(since)
    cs = query_loki_crowdsec(since)
    ids = query_loki_ids(since)
    cf = query_cloudflare(since)
    ub = query_uberspace(since)
    combined = f2b + cs + ids + cf + ub
    combined.sort(key=lambda a: a.get("ts_epoch", 0))
    return combined


def poll_loop():
    """Background thread that polls Loki."""
    while True:
        attacks = query_all()
        with _lock:
            _cache["attacks"] = attacks
            _cache["last_update"] = time.time()
            _cache["total_bans"] = len(attacks)
        time.sleep(QUERY_INTERVAL)


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/attacks")
def get_attacks():
    range_param = request.args.get("range", "")
    if range_param and range_param in VALID_RANGES:
        attacks = query_all(since=range_param)
        return jsonify({
            "attacks": attacks,
            "total": len(attacks),
            "last_update": time.time(),
            "target": {"lat": TARGET_LAT, "lon": TARGET_LON},
            "range": range_param,
        })
    with _lock:
        return jsonify({
            "attacks": _cache["attacks"],
            "total": _cache["total_bans"],
            "last_update": _cache["last_update"],
            "target": {"lat": TARGET_LAT, "lon": TARGET_LON},
            "range": "live",
        })


@app.route("/api/health")
def health():
    with _lock:
        age = time.time() - _cache["last_update"] if _cache["last_update"] else -1
    with _geoip_lock:
        geo_cache_size = len(_geoip_cache)
    return jsonify({
        "status": "ok",
        "cache_age_seconds": round(age, 1),
        "geoip_cache_size": geo_cache_size,
    })


# Start poll thread
poll_thread = threading.Thread(target=poll_loop, daemon=True)
poll_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
