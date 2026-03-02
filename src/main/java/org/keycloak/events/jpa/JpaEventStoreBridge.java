/*
 * Copyright 2026 Adrian Ana and contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package org.keycloak.events.jpa;

import jakarta.persistence.EntityManager;
import org.keycloak.models.KeycloakSession;

/**
 * Bridge class to access package-private/protected methods on
 * {@link JpaEventStoreProvider} from the enrichment SPI package.
 * <p>
 * This class MUST be in the {@code org.keycloak.events.jpa} package
 * to access the {@code protected clearExpiredAdminEvents()} method.
 */
public final class JpaEventStoreBridge {

    private JpaEventStoreBridge() {} // utility class

    /**
     * Clear expired admin events using a fresh JPA provider instance.
     * Called from the enrichment factory's {@code InvalidationHandler}.
     */
    public static void clearExpiredAdminEvents(KeycloakSession session, EntityManager em) {
        JpaEventStoreProvider provider = new JpaEventStoreProvider(session, em);
        provider.clearExpiredAdminEvents();
    }
}
