/*
 * Copyright 2026 Adrian Ana and contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package net.sinenomine.keycloak.enrichment;

import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.AddressNotFoundException;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.maxmind.geoip2.record.City;
import com.maxmind.geoip2.record.Country;
import com.maxmind.geoip2.record.Location;
import com.maxmind.geoip2.record.Subdivision;

import org.jboss.logging.Logger;

import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;

/**
 * Thread-safe GeoIP lookup service using MaxMind GeoLite2 databases.
 * Designed as a singleton on the factory — shared across all provider instances.
 */
public class GeoIPService {

    private static final Logger logger = Logger.getLogger(GeoIPService.class);

    /** Known VPN/hosting ASN organization name patterns (lowercase). */
    private static final List<String> VPN_ASN_PATTERNS = List.of(
            "nordvpn", "expressvpn", "cyberghost", "surfshark",
            "private internet access", "mullvad", "protonvpn",
            "ipvanish", "tunnelbear", "windscribe", "hotspot shield",
            "digital ocean", "linode", "vultr", "ovh", "hetzner",
            "amazon", "google cloud", "microsoft azure", "oracle cloud",
            "choopa", "m247", "datacamp", "leaseweb"
    );

    private final DatabaseReader cityReader;
    private final DatabaseReader asnReader;  // nullable

    /**
     * @param cityDbPath  Path to GeoLite2-City.mmdb (required)
     * @param asnDbPath   Path to GeoLite2-ASN.mmdb (optional — null disables VPN detection)
     */
    public GeoIPService(String cityDbPath, String asnDbPath) throws IOException {
        File cityFile = new File(cityDbPath);
        if (!cityFile.exists()) {
            throw new IOException("GeoLite2-City database not found: " + cityDbPath);
        }
        this.cityReader = new DatabaseReader.Builder(cityFile)
                .withCache(new CHMCache(4096))
                .fileMode(com.maxmind.db.Reader.FileMode.MEMORY)
                .build();
        logger.infof("GeoLite2-City database loaded: %s", cityDbPath);

        if (asnDbPath != null) {
            File asnFile = new File(asnDbPath);
            if (asnFile.exists()) {
                this.asnReader = new DatabaseReader.Builder(asnFile)
                        .withCache(new CHMCache(4096))
                        .fileMode(com.maxmind.db.Reader.FileMode.MEMORY)
                        .build();
                logger.infof("GeoLite2-ASN database loaded: %s", asnDbPath);
            } else {
                this.asnReader = null;
                logger.warnf("GeoLite2-ASN database not found: %s — VPN detection disabled", asnDbPath);
            }
        } else {
            this.asnReader = null;
        }
    }

    /**
     * Lookup GeoIP data for an IP address.
     * Returns {@link GeoResult#EMPTY} for private/loopback IPs or lookup failures.
     * Never throws — all exceptions are caught and logged.
     */
    public GeoResult lookup(String ipAddress) {
        if (ipAddress == null || ipAddress.isBlank()) {
            return GeoResult.EMPTY;
        }

        InetAddress addr;
        try {
            addr = InetAddress.getByName(ipAddress);
        } catch (UnknownHostException e) {
            logger.debugf("Invalid IP address: %s", ipAddress);
            return GeoResult.EMPTY;
        }

        if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
            return GeoResult.EMPTY;
        }

        try {
            CityResponse city = cityReader.city(addr);

            Country country = city.getCountry();
            Subdivision subdivision = city.getMostSpecificSubdivision();
            City cityRecord = city.getCity();
            Location location = city.getLocation();

            String countryCode = country != null ? country.getIsoCode() : null;
            String regionName = subdivision != null ? subdivision.getName() : null;
            String cityName = cityRecord != null ? cityRecord.getName() : null;

            String lat = null;
            String lon = null;
            if (location != null) {
                if (location.getLatitude() != null) {
                    lat = BigDecimal.valueOf(location.getLatitude())
                            .setScale(2, RoundingMode.HALF_UP).toPlainString();
                }
                if (location.getLongitude() != null) {
                    lon = BigDecimal.valueOf(location.getLongitude())
                            .setScale(2, RoundingMode.HALF_UP).toPlainString();
                }
            }

            Boolean isVpn = detectVpn(addr);

            return new GeoResult(countryCode, regionName, cityName, lat, lon, isVpn);

        } catch (AddressNotFoundException e) {
            logger.debugf("IP not found in GeoLite2 database: %s", ipAddress);
            return GeoResult.EMPTY;
        } catch (Exception e) {
            logger.warnf("GeoIP lookup failed for %s: %s", ipAddress, e.getMessage());
            return GeoResult.EMPTY;
        }
    }

    private Boolean detectVpn(InetAddress addr) {
        if (asnReader == null) {
            return null;  // ASN DB unavailable — omit geo_is_vpn from event details
        }
        try {
            AsnResponse asn = asnReader.asn(addr);
            String org = asn.getAutonomousSystemOrganization();
            if (org != null) {
                String orgLower = org.toLowerCase(Locale.ROOT);
                return VPN_ASN_PATTERNS.stream().anyMatch(orgLower::contains);
            }
        } catch (Exception e) {
            logger.debugf("ASN lookup failed for %s: %s", addr.getHostAddress(), e.getMessage());
        }
        return false;
    }

    public void close() {
        try {
            cityReader.close();
        } catch (IOException e) {
            logger.warn("Error closing City database reader", e);
        }
        if (asnReader != null) {
            try {
                asnReader.close();
            } catch (IOException e) {
                logger.warn("Error closing ASN database reader", e);
            }
        }
    }
}
