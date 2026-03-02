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

import org.jboss.logging.Logger;
import ua_parser.Client;
import ua_parser.Parser;

/**
 * Thread-safe User-Agent parsing service using uap-java.
 * Designed as a singleton on the factory.
 */
public class UserAgentService {

    private static final Logger logger = Logger.getLogger(UserAgentService.class);

    /** Maximum UA string length before truncation (ReDoS defense). */
    private final int maxUaLength;

    private final Parser parser;

    public UserAgentService(int maxUaLength) {
        this.maxUaLength = maxUaLength;
        this.parser = new Parser();
        logger.infof("UA parser initialized (max UA length: %d)", maxUaLength);
    }

    /**
     * Parse a User-Agent string into browser, OS, and device type.
     * Returns {@link UAResult#EMPTY} for null/blank input.
     * Never throws.
     */
    public UAResult parse(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return UAResult.EMPTY;
        }

        // Truncate to defend against ReDoS via regex backtracking
        String ua = userAgent.length() > maxUaLength
                ? userAgent.substring(0, maxUaLength)
                : userAgent;

        try {
            Client client = parser.parse(ua);

            String browser = formatBrowser(client);
            String os = formatOs(client);
            String deviceType = classifyDevice(client);

            if (browser == null && os == null && deviceType == null) {
                return UAResult.EMPTY;
            }

            return new UAResult(browser, os, deviceType);

        } catch (Exception e) {
            logger.debugf("UA parse failed: %s", e.getMessage());
            return UAResult.EMPTY;
        }
    }

    private String formatBrowser(Client client) {
        if (client.userAgent == null || "Other".equals(client.userAgent.family)) {
            return null;
        }
        String version = client.userAgent.major;
        if (version != null && !version.isEmpty()) {
            return client.userAgent.family + " " + version;
        }
        return client.userAgent.family;
    }

    private String formatOs(Client client) {
        if (client.os == null || "Other".equals(client.os.family)) {
            return null;
        }
        String version = client.os.major;
        if (version != null && !version.isEmpty()) {
            return client.os.family + " " + version;
        }
        return client.os.family;
    }

    private String classifyDevice(Client client) {
        if (client.device == null || client.device.family == null) {
            return "desktop";
        }
        String family = client.device.family.toLowerCase();
        if (family.contains("spider") || family.contains("bot") || family.contains("crawler")) {
            return "bot";
        }
        if (family.contains("iphone") || family.contains("android") || family.contains("mobile")) {
            return "mobile";
        }
        if (family.contains("ipad") || family.contains("tablet")) {
            return "tablet";
        }
        return "desktop";
    }
}
