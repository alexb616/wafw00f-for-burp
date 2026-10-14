package com.wafw00f.burp.core;

/**
 * Cómo se obtuvieron las respuestas que se evalúan contra las firmas.
 */
public enum DetectionMode {
    /** Solo tráfico ya capturado por el proxy; no se lanza ninguna request nueva. */
    PASSIVE("Passive"),
    /** Sondeo activo estilo wafw00f: request normal + request de ataque. */
    ACTIVE("Active");

    private final String label;

    DetectionMode(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
