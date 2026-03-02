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

import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventStoreProviderFactory;
import org.keycloak.events.jpa.JpaEventStoreProvider;
import org.keycloak.events.jpa.JpaEventStoreBridge;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.InvalidationHandler;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.datastore.PeriodicEventInvalidation;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.List;

/**
 * Factory for {@link EnrichingEventStoreProvider}. Replaces the built-in
 * JPA event store by using the same provider ID ("jpa") with higher order.
 *
 * <p>Singleton services (GeoIPService, UserAgentService) are initialized
 * in {@link #init(Config.Scope)} and shared across all provider instances.</p>
 *
 * <p>Implements {@link InvalidationHandler} to forward periodic admin event
 * cleanup — the built-in JpaEventStoreProviderFactory is fully replaced
 * when this factory loads, so its InvalidationHandler is lost.</p>
 *
 * <p>This product includes GeoLite2 Data created by MaxMind,
 * available from <a href="https://www.maxmind.com">https://www.maxmind.com</a>.</p>
 */
public class EnrichingEventStoreProviderFactory
        implements EventStoreProviderFactory, InvalidationHandler {

    private static final Logger logger = Logger.getLogger(EnrichingEventStoreProviderFactory.class);

    /** Same ID as built-in JPA store — we replace it via higher order(). */
    public static final String ID = "jpa";

    private GeoIPService geoIPService;
    private UserAgentService userAgentService;
    private boolean enrichmentEnabled;

    @Override
    public EventStoreProvider create(KeycloakSession session) {
        // Create the delegate JPA provider directly (same as built-in factory)
        JpaConnectionProvider connection = session.getProvider(JpaConnectionProvider.class);
        JpaEventStoreProvider delegate = new JpaEventStoreProvider(
                session, connection.getEntityManager());

        return new EnrichingEventStoreProvider(
                delegate, session, geoIPService, userAgentService, enrichmentEnabled);
    }

    @Override
    public void init(Config.Scope config) {
        enrichmentEnabled = config.getBoolean("enrichment-enabled", true);

        if (!enrichmentEnabled) {
            logger.info("Event enrichment is DISABLED by configuration");
            return;
        }

        // GeoIP
        String mmdbPath = config.get("mmdb-path");
        String asnMmdbPath = config.get("asn-mmdb-path");
        if (mmdbPath != null) {
            try {
                geoIPService = new GeoIPService(mmdbPath, asnMmdbPath);
                logger.info("GeoIP enrichment enabled");
            } catch (IOException e) {
                logger.errorf("Failed to initialize GeoIP service: %s — geo enrichment disabled", e.getMessage());
            }
        } else {
            logger.info("No mmdb-path configured — GeoIP enrichment disabled");
        }

        // User-Agent
        int maxUaLength = config.getInt("max-ua-length", 512);
        try {
            userAgentService = new UserAgentService(maxUaLength);
            logger.info("User-Agent enrichment enabled");
        } catch (Exception e) {
            logger.errorf("Failed to initialize UA parser: %s — UA enrichment disabled", e.getMessage());
        }

        // MaxMind attribution (required by GeoLite2 EULA)
        if (geoIPService != null) {
            logger.info("This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com");
        }

        logger.infof("Event enrichment SPI initialized (geo=%s, ua=%s)",
                geoIPService != null ? "enabled" : "disabled",
                userAgentService != null ? "enabled" : "disabled");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No-op
    }

    @Override
    public void close() {
        if (geoIPService != null) {
            geoIPService.close();
        }
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public int order() {
        return 1;  // Higher than built-in JPA factory (0)
    }

    /**
     * Forward periodic admin event cleanup via JpaEventStoreBridge.
     * The built-in JpaEventStoreProviderFactory is fully replaced when our
     * factory loads, so its InvalidationHandler is lost. We must handle it.
     */
    @Override
    public void invalidate(KeycloakSession session, InvalidableObjectType type, Object... params) {
        if (type == PeriodicEventInvalidation.JPA_EVENT_STORE) {
            JpaConnectionProvider connection = session.getProvider(JpaConnectionProvider.class);
            JpaEventStoreBridge.clearExpiredAdminEvents(session, connection.getEntityManager());
        }
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return ProviderConfigurationBuilder.create()
                .property().name("mmdb-path").type("string")
                .helpText("Path to GeoLite2-City.mmdb file").add()
                .property().name("asn-mmdb-path").type("string")
                .helpText("Path to GeoLite2-ASN.mmdb file for VPN detection").add()
                .property().name("enrichment-enabled").type("boolean")
                .helpText("Enable/disable event enrichment").defaultValue("true").add()
                .property().name("max-ua-length").type("int")
                .helpText("Max User-Agent string length before truncation (ReDoS defense)").defaultValue("512").add()
                .build();
    }
}
