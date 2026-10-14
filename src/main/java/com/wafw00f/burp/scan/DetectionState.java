package com.wafw00f.burp.scan;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Estado de deduplicación: qué WAFs se han reportado ya por host, para no crear
 * issues repetidos cuando el mismo host genera mucho tráfico en el proxy.
 */
public final class DetectionState {

    private final Map<String, Set<String>> reportedByHost = new ConcurrentHashMap<>();

    /** Registra (host, waf); devuelve true si es la primera vez (hay que reportar). */
    public boolean shouldReport(String host, String wafName) {
        return reportedByHost
                .computeIfAbsent(host, h -> ConcurrentHashMap.newKeySet())
                .add(wafName);
    }

    /** ¿Ya se ha reportado algún WAF para este host? */
    public boolean hasAny(String host) {
        Set<String> set = reportedByHost.get(host);
        return set != null && !set.isEmpty();
    }

    public void reset(String host) {
        reportedByHost.remove(host);
    }

    public void resetAll() {
        reportedByHost.clear();
    }
}
