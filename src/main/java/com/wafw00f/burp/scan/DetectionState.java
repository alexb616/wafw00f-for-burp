package com.wafw00f.burp.scan;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Deduplication state: which WAFs have already been reported per host, so we
 * don't create repeated issues when a host produces a lot of proxy traffic.
 */
public final class DetectionState {

    private final Map<String, Set<String>> reportedByHost = new ConcurrentHashMap<>();

    /** Records (host, waf); returns true the first time (callers should report). */
    public boolean shouldReport(String host, String wafName) {
        return reportedByHost
                .computeIfAbsent(host, h -> ConcurrentHashMap.newKeySet())
                .add(wafName);
    }

    /** Whether any WAF has already been reported for this host. */
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
