package com.wafw00f.burp.engine;

/**
 * Par (respuesta normal, respuesta de ataque) sobre el que se evalúan las firmas.
 * En modo activo son dos respuestas distintas (wafw00f: self.rq y self.attackres).
 * En modo pasivo ambas apuntan a la misma respuesta observada, de modo que las
 * firmas de página de bloqueo (attack=true) solo saltan si el tráfico capturado
 * ya era una página de bloqueo.
 */
public final class ResponsePair {

    private final ResponseView normal;
    private final ResponseView attack;

    public ResponsePair(ResponseView normal, ResponseView attack) {
        this.normal = normal;
        this.attack = attack;
    }

    /** Par pasivo: la misma respuesta hace de normal y de ataque. */
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
