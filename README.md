# Keycloak Event Enrichment SPI

A Keycloak SPI extension that enriches authentication events with GeoIP location data and parsed User-Agent information before persistence.

![Keycloak](https://img.shields.io/badge/Keycloak-26.x-blue)
![License](https://img.shields.io/github/license/AdrianIAna/keycloak-event-enrichment)

## Why

Keycloak stores authentication events (login, logout, login error, etc.) with the client IP address, but does not store where the user is logging in from or what device they're using. Applications that need this data — for login history, security dashboards, or anomaly detection — must perform their own GeoIP lookups and User-Agent parsing, duplicating effort across every client.

This extension moves that enrichment into Keycloak itself, so the data is stored once at the source and every consumer (Account Console, Admin API, custom applications) receives it automatically.

## How It Works

This extension wraps Keycloak's built-in JPA event store (`JpaEventStoreProvider`). When an authentication event (LOGIN, LOGOUT, LOGIN_ERROR, etc.) occurs, the provider:

1. Looks up the client IP in a MaxMind GeoLite2 database for location and VPN detection
2. Parses the User-Agent header for browser, OS, and device type
3. Adds `geo_*` and `ua_*` fields to the event's `details` map
4. Delegates to the standard JPA store for persistence

Enrichment failures never block event persistence — if a GeoIP lookup fails or the MMDB file is missing, the event is stored without enrichment. Admin events (client updates, role changes, etc.) are not enriched.

## Compatibility

| Extension Version | Keycloak Version |
|-------------------|------------------|
| 1.0.x             | 26.x             |

> This extension is compiled and tested against the Keycloak version shown above. It may work with other versions but is not guaranteed.

## Installation

1. Copy the shaded JAR to `/opt/keycloak/providers/`
2. Copy MaxMind MMDB files to a persistent path (e.g., `/opt/keycloak/conf/geoip/`)
3. Run `bin/kc.sh build` to register the provider (include build-time SPI options)
4. Add configuration options to your `kc.sh start` command

```bash
cp target/keycloak-event-enrichment-1.0.0.jar /opt/keycloak/providers/
mkdir -p /opt/keycloak/conf/geoip
cp GeoLite2-City.mmdb /opt/keycloak/conf/geoip/
cp GeoLite2-ASN.mmdb /opt/keycloak/conf/geoip/  # optional
bin/kc.sh build --spi-events-store--jpa--enrichment-enabled=true
```

## Configuration

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `--spi-events-store--jpa--mmdb-path` | `KC_SPI_EVENTS_STORE__JPA__MMDB_PATH` | _(none)_ | Path to GeoLite2-City.mmdb (required for GeoIP) |
| `--spi-events-store--jpa--asn-mmdb-path` | `KC_SPI_EVENTS_STORE__JPA__ASN_MMDB_PATH` | _(none)_ | Path to GeoLite2-ASN.mmdb (optional, for VPN detection) |
| `--spi-events-store--jpa--enrichment-enabled` | `KC_SPI_EVENTS_STORE__JPA__ENRICHMENT_ENABLED` | `true` | Enable/disable event enrichment (build-time) |
| `--spi-events-store--jpa--max-ua-length` | `KC_SPI_EVENTS_STORE__JPA__MAX_UA_LENGTH` | `512` | Max User-Agent string length before truncation (ReDoS defense) |

## Enrichment Fields

| Field | Example | Source |
|-------|---------|--------|
| `geo_country` | `US` | GeoLite2-City |
| `geo_region` | `Ohio` | GeoLite2-City |
| `geo_city` | `North Royalton` | GeoLite2-City |
| `geo_lat` | `41.31` | GeoLite2-City (rounded to 2 decimals) |
| `geo_lon` | `-81.72` | GeoLite2-City (rounded to 2 decimals) |
| `geo_is_vpn` | `false` | GeoLite2-ASN (org name matching) |
| `ua_browser` | `Chrome 131` | uap-java |
| `ua_os` | `Windows 10` | uap-java |
| `ua_device_type` | `desktop` | uap-java |

## Building from Source

Requires Java 17+ and Maven 3.8+.

```bash
mvn clean package
```

Output: `target/keycloak-event-enrichment-1.0.0.jar` (shaded — includes MaxMind GeoIP2 library with package relocation)

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

## License

[Apache License 2.0](LICENSE)

## Attribution

This product uses GeoLite2 Data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

Users must download GeoLite2 databases separately from MaxMind (free with account registration).
