package com.wafw00f.burp.engine;

/**
 * (normal response, attack response) pair against which signatures are
 * evaluated. In active mode they are two different responses (wafw00f:
 * self.rq and self.attackres). In passive mode both point to the same
 * observed response, so block-page signatures (attack=true) only fire if the
 * captured traffic was already a block page.
 */
public final class ResponsePair {

    private final ResponseView normal;
    private final ResponseView attack;

    public ResponsePair(ResponseView normal, ResponseView attack) {
        this.normal = normal;
        this.attack = attack;
    }

    /** Passive pair: the same response plays both the normal and attack role. */
    public static ResponsePair passive(ResponseView observed) {
        return new ResponsePair(observed, observed);
    }

    public ResponseView pick(boolean attack) {
        return attack ? this.attack : this.normal;
    }

    public ResponseView normal() {
        return normal;
    }

    public ResponseView attack() {
        return attack;
    }
}
