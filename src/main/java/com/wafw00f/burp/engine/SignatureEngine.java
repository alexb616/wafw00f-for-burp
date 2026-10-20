package com.wafw00f.burp.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Identification engine: walks the signatures in priority order and returns
 * those that match the response pair. Equivalent to wafw00f's identwaf().
 */
public final class SignatureEngine {

    private final SignatureStore store;

    public SignatureEngine(SignatureStore store) {
        this.store = store;
    }

    public static SignatureEngine create(Consumer<String> logger) {
        return new SignatureEngine(SignatureStore.loadFromResources(logger));
    }

    public int signatureCount() {
        return store.size();
    }

    public int patternErrors() {
        return store.patternErrors();
    }

    /**
     * Identifies the WAFs that match the response pair.
     *
     * @param rp      (normal, attack) pair
     * @param findAll if false, stop at the first match (wafw00f's default)
     * @return WAF names ("Firewall (Manufacturer)") in priority order
     */
    public List<Signature> identify(ResponsePair rp, boolean findAll) {
        List<Signature> detected = new ArrayList<>();
        for (Signature sig : store.signatures()) {
            boolean match;
            try {
                match = sig.matches(rp);
            } catch (RuntimeException ex) {
                match = false; // a broken signature must not tank the whole detection
            }
            if (match) {
                detected.add(sig);
                if (!findAll) {
                    break;
                }
            }
        }
        return detected;
    }
}
