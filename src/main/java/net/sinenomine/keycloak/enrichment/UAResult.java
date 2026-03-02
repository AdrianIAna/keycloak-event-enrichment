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

/**
 * Immutable result of a User-Agent parse.
 */
public record UAResult(
        String browser,
        String os,
        String deviceType
) {
    /** Empty result when UA header is null or unparseable. */
    public static final UAResult EMPTY = new UAResult(null, null, null);
}
