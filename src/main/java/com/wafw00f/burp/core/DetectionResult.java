package com.wafw00f.burp.core;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Un resultado de detección sobre un host, con la evidencia que lo motivó.
 * Puede representar un WAF concreto, la detección genérica, o la ausencia de WAF
 * tras un sondeo activo ({@link #isNone()}).
 */
public final class DetectionResult {

    public static final String GENERIC = "Generic";
    public static final String NONE = "None";

    private final String wafName;        // p.ej. "Cloudflare (Cloudflare Inc.)", "Generic" o "None"
    private final String firewall;       // p.ej. "Cloudflare"
    private final String manufacturer;   // p.ej. "Cloudflare Inc."
    private final DetectionMode mode;
    private final String evidence;       // descripción legible del motivo
    private final HttpRequestResponse evidenceExchange; // puede ser null
    private final boolean none;          // true = sondeo hecho, ningún WAF

    public DetectionResult(String wafName, String firewall, String manufacturer,
                           DetectionMode mode, String evidence,
                           HttpRequestResponse evidenceExchange, boolean none) {
        this.wafName = wafName;
        this.firewall = firewall;
        this.manufacturer = manufacturer;
        this.mode = mode;
        this.evidence = evidence;
        this.evidenceExchange = evidenceExchange;
        this.none = none;
    }

    /**
     * Construye el resultado a partir del NAME de wafw00f ("Firewall (Fabricante)"),
     * replicando buildResultRecord() de wafw00f/main.py.
     */
    public static DetectionResult fromWafName(String wafName, DetectionMode mode,
                                              String evidence, HttpRequestResponse exchange) {
        String firewall;
        String manufacturer;
        if (wafName == null) {
            firewall = NONE;
            manufacturer = NONE;
        } else if (wafName.contains("(")) {
            int idx = wafName.indexOf('(');
            firewall = wafName.substring(0, idx).trim();
            manufacturer = wafName.substring(idx + 1).replace(")", "").trim();
        } else {
            firewall = wafName.trim();
            manufacturer = "Unknown";
        }
        return new DetectionResult(wafName, firewall, manufacturer, mode, evidence, exchange, false);
    }

    public static DetectionResult generic(DetectionMode mode, String evidence, HttpRequestResponse exchange) {
        return new DetectionResult(GENERIC, GENERIC, "Unknown", mode, evidence, exchange, false);
    }

    /** Sondeo realizado sin detectar ningún WAF. */
    public static DetectionResult none(DetectionMode mode, String evidence, HttpRequestResponse exchange) {
        return new DetectionResult(NONE, NONE, NONE, mode, evidence, exchange, true);
    }

    public String wafName() {
        return wafName;
    }

    public String firewall() {
        return firewall;
    }

    public String manufacturer() {
        return manufacturer;
    }

    public DetectionMode mode() {
        return mode;
    }

    public String evidence() {
        return evidence;
    }

    public HttpRequestResponse evidenceExchange() {
        return evidenceExchange;
    }

    public boolean isGeneric() {
        return GENERIC.equals(wafName) && !none;
    }

    public boolean isNone() {
        return none;
    }
}
