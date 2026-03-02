package net.sinenomine.keycloak.enrichment;

import org.keycloak.events.Event;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EnrichingEventStoreProviderTest {

    @Mock EventStoreProvider delegate;
    @Mock KeycloakSession session;
    @Mock GeoIPService geoIPService;
    @Mock UserAgentService userAgentService;

    private EnrichingEventStoreProvider provider;

    @BeforeEach
    void setUp() {
        provider = new EnrichingEventStoreProvider(
                delegate, session, geoIPService, userAgentService, true);
    }

    @Test
    void onEventEnrichesAndDelegates() {
        Event event = new Event();
        event.setIpAddress("1.1.1.1");
        event.setDetails(new HashMap<>(Map.of("code_id", "abc")));

        when(geoIPService.lookup("1.1.1.1"))
                .thenReturn(new GeoResult("US", "Virginia", "Ashburn", "39.04", "-77.49", false));

        provider.onEvent(event);

        verify(delegate).onEvent(event);
        assertEquals("US", event.getDetails().get("geo_country"));
        assertEquals("Virginia", event.getDetails().get("geo_region"));
        assertEquals("Ashburn", event.getDetails().get("geo_city"));
        assertEquals("false", event.getDetails().get("geo_is_vpn"));
        // Original details preserved
        assertEquals("abc", event.getDetails().get("code_id"));
    }

    @Test
    void onEventHandlesNullDetails() {
        Event event = new Event();
        event.setIpAddress("1.1.1.1");
        // details is null by default

        when(geoIPService.lookup("1.1.1.1")).thenReturn(GeoResult.EMPTY);

        provider.onEvent(event);

        verify(delegate).onEvent(event);
        assertNotNull(event.getDetails()); // Should have been initialized
    }

    @Test
    void onEventDelegatesEvenWhenEnrichmentFails() {
        Event event = new Event();
        event.setIpAddress("bad");

        when(geoIPService.lookup("bad")).thenThrow(new RuntimeException("boom"));

        provider.onEvent(event);

        // Delegate MUST still be called
        verify(delegate).onEvent(event);
    }

    @Test
    void adminEventNotEnriched() {
        AdminEvent adminEvent = new AdminEvent();
        provider.onEvent(adminEvent, true);

        verify(delegate).onEvent(adminEvent, true);
        verifyNoInteractions(geoIPService);
        verifyNoInteractions(userAgentService);
    }

    @Test
    void enrichmentDisabledSkipsEnrichment() {
        EnrichingEventStoreProvider disabled = new EnrichingEventStoreProvider(
                delegate, session, geoIPService, userAgentService, false);

        Event event = new Event();
        event.setIpAddress("1.2.3.4");

        disabled.onEvent(event);

        verify(delegate).onEvent(event);
        verifyNoInteractions(geoIPService);
        verifyNoInteractions(userAgentService);
    }
}
