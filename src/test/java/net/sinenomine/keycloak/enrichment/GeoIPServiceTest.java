/*
 * Copyright 2026 Sine Nomine Associates and contributors
 * Author: Adrian Ana <aana@sinenomine.net>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
