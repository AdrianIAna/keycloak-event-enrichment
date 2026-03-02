package net.sinenomine.keycloak.enrichment;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EnrichingEventStoreProviderFactoryTest {

    @Test
    void getIdReturnsJpa() {
        EnrichingEventStoreProviderFactory factory = new EnrichingEventStoreProviderFactory();
        assertEquals("jpa", factory.getId());
    }

    @Test
    void orderIsHigherThanDefault() {
        EnrichingEventStoreProviderFactory factory = new EnrichingEventStoreProviderFactory();
        assertTrue(factory.order() > 0, "order() must be > 0 to replace built-in JPA factory");
    }
}
