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

import org.keycloak.events.Event;
import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AdminEventQuery;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.Map;

/**
 * EventStoreProvider wrapper that enriches user authentication events
 * with GeoIP location and parsed User-Agent data before delegating
 * to the JPA store for persistence.
 *
 * <p>Admin events are NOT enriched — they represent internal admin
 * operations, not end-user authentication.</p>
 */
public class EnrichingEventStoreProvider implements EventStoreProvider {

    private static final Logger logger = Logger.getLogger(EnrichingEventStoreProvider.class);

    private final EventStoreProvider delegate;
    private final KeycloakSession session;
    private final GeoIPService geoIPService;       // nullable
    private final UserAgentService userAgentService; // nullable
    private final boolean enrichmentEnabled;

    public EnrichingEventStoreProvider(
            EventStoreProvider delegate,
            KeycloakSession session,
            GeoIPService geoIPService,
            UserAgentService userAgentService,
            boolean enrichmentEnabled) {
        this.delegate = delegate;
        this.session = session;
        this.geoIPService = geoIPService;
        this.userAgentService = userAgentService;
        this.enrichmentEnabled = enrichmentEnabled;
    }

    @Override
    public void onEvent(Event event) {
        if (enrichmentEnabled) {
            try {
                enrich(event);
            } catch (Exception e) {
                // Enrichment failure MUST NOT block event persistence
                logger.warnf("Event enrichment failed for %s: %s", event.getType(), e.getMessage());
            }
        }
        delegate.onEvent(event);
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Admin events are NOT enriched — delegate directly
        delegate.onEvent(event, includeRepresentation);
    }

    private void enrich(Event event) {
        Map<String, String> details = event.getDetails();
        if (details == null) {
            details = new HashMap<>();
        } else {
            details = new HashMap<>(details); // defensive copy — safe if source is unmodifiable
        }
        event.setDetails(details);

        // GeoIP enrichment
        if (geoIPService != null) {
            GeoResult geo = geoIPService.lookup(event.getIpAddress());
            if (geo != GeoResult.EMPTY) {
                putIfNotNull(details, "geo_country", geo.country());
                putIfNotNull(details, "geo_region", geo.region());
                putIfNotNull(details, "geo_city", geo.city());
                putIfNotNull(details, "geo_lat", geo.lat());
                putIfNotNull(details, "geo_lon", geo.lon());
                if (geo.isVpn() != null) {
                    details.put("geo_is_vpn", String.valueOf(geo.isVpn()));
                }
            }
        }

        // User-Agent enrichment
        if (userAgentService != null) {
            String ua = getUserAgent();
            if (ua != null) {
                UAResult parsed = userAgentService.parse(ua);
                if (parsed != UAResult.EMPTY) {
                    putIfNotNull(details, "ua_browser", parsed.browser());
                    putIfNotNull(details, "ua_os", parsed.os());
                    putIfNotNull(details, "ua_device_type", parsed.deviceType());
                }
            }
        }
    }

    private String getUserAgent() {
        try {
            var context = session.getContext();
            if (context == null) return null;
            var request = context.getHttpRequest();
            if (request == null) return null;
            var headers = request.getHttpHeaders();
            if (headers == null) return null;
            return headers.getHeaderString("User-Agent");
        } catch (Exception e) {
            logger.debugf("Could not read User-Agent header: %s", e.getMessage());
            return null;
        }
    }

    private static void putIfNotNull(Map<String, String> map, String key, String value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    // --- Pure delegation for all other methods ---

    @Override
    public EventQuery createQuery() {
        return delegate.createQuery();
    }

    @Override
    public AdminEventQuery createAdminQuery() {
        return delegate.createAdminQuery();
    }

    @Override
    public void clear() {
        delegate.clear();
    }

    @Override
    public void clear(RealmModel realm) {
        delegate.clear(realm);
    }

    @Override
    public void clear(RealmModel realm, long olderThan) {
        delegate.clear(realm, olderThan);
    }

    @Override
    public void clearExpiredEvents() {
        delegate.clearExpiredEvents();
    }

    @Override
    public void clearAdmin() {
        delegate.clearAdmin();
    }

    @Override
    public void clearAdmin(RealmModel realm) {
        delegate.clearAdmin(realm);
    }

    @Override
    public void clearAdmin(RealmModel realm, long olderThan) {
        delegate.clearAdmin(realm, olderThan);
    }

    @Override
    public void close() {
        delegate.close();
    }
}
