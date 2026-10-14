package com.wafw00f.burp.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Motor de identificación: recorre las firmas en orden de prioridad y devuelve
 * las que casan con el par de respuestas. Equivale a identwaf() de wafw00f.
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
     * Identifica los WAF que casan con el par de respuestas.
     *
     * @param rp      par (normal, ataque)
     * @param findAll si false, para en la primera coincidencia (como wafw00f por defecto)
     * @return nombres de WAF ("Firewall (Fabricante)") en orden de prioridad
     */
    public List<Signature> identify(ResponsePair rp, boolean findAll) {
        List<Signature> detected = new ArrayList<>();
        for (Signature sig : store.signatures()) {
            boolean match;
            try {
                match = sig.matches(rp);
            } catch (RuntimeException ex) {
                match = false; // una firma defectuosa no debe tumbar la detección
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
