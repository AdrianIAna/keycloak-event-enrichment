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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserAgentServiceTest {

    private static UserAgentService service;

    @BeforeAll
    static void setUp() {
        service = new UserAgentService(512);
    }

    @Test
    void parseReturnsEmptyForNull() {
        assertEquals(UAResult.EMPTY, service.parse(null));
    }

    @Test
    void parseReturnsEmptyForBlank() {
        assertEquals(UAResult.EMPTY, service.parse("  "));
    }

    @Test
    void parseChromeOnWindows() {
        UAResult result = service.parse(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
        assertEquals("Chrome 131", result.browser());
        assertEquals("Windows 10", result.os());
        assertEquals("desktop", result.deviceType());
    }

    @Test
    void parseSafariOnIPhone() {
        UAResult result = service.parse(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1");
        assertNotNull(result.browser());
        assertNotNull(result.os());
        assertEquals("mobile", result.deviceType());
    }

    @Test
    void truncatesLongUserAgent() {
        // 600-char UA string — should be truncated to 512 before parsing, not throw
        String longUa = "Mozilla/5.0 " + "A".repeat(600);
        UAResult result = service.parse(longUa);
        // Should not throw, result can be anything
        assertNotNull(result);
    }
}
