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

/**
 * Immutable result of a GeoIP lookup.
 */
public record GeoResult(
        String country,
        String region,
        String city,
        String lat,
        String lon,
        Boolean isVpn   // null when ASN DB unavailable (omit from event details)
) {
    /** Empty result when lookup fails or IP is private. */
    public static final GeoResult EMPTY = new GeoResult(null, null, null, null, null, null);
}
