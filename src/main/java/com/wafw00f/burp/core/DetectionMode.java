package com.wafw00f.burp.core;

/**
 * How the responses evaluated against the signatures were obtained.
 */
public enum DetectionMode {
    /** Only traffic already captured by the proxy; no new request is sent. */
    PASSIVE("Passive"),
    /** wafw00f-style active probe: normal request plus attack request. */
    ACTIVE("Active");

    private final String label;

    DetectionMode(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
