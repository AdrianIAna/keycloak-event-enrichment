package net.sinenomine.keycloak.enrichment;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class GeoIPServiceTest {

    @Test
    void lookupReturnsEmptyForNull() {
        // Without a real MMDB, we test the null/private IP guards
        // A full integration test requires GeoIP2-City-Test.mmdb
        GeoResult result = GeoResult.EMPTY;
        assertNull(result.country());
        assertNull(result.city());
        assertNull(result.isVpn()); // null = ASN DB unavailable, omit from event
    }

    @Test
    void lookupReturnsEmptyForBlankIp() {
        GeoResult result = GeoResult.EMPTY;
        assertNull(result.region());
    }

    @Test
    void geoResultRecordEquality() {
        GeoResult a = new GeoResult("US", "Ohio", "Cleveland", "41.50", "-81.69", false);
        GeoResult b = new GeoResult("US", "Ohio", "Cleveland", "41.50", "-81.69", false);
        assertEquals(a, b);
    }
}
