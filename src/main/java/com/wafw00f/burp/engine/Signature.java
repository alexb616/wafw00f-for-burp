package com.wafw00f.burp.engine;

/**
 * Una firma de WAF: nombre "Firewall (Fabricante)", slug (fichero original)
 * y el árbol de condiciones. {@link #matches} equivale a is_waf(self) de wafw00f.
 */
public final class Signature {

    private final String name;
    private final String slug;
    private final Condition root;

    public Signature(String name, String slug, Condition root) {
        this.name = name;
        this.slug = slug;
        this.root = root;
    }

    public String name() {
        return name;
    }

    public String slug() {
        return slug;
    }

    public boolean matches(ResponsePair rp) {
        return root.eval(rp);
    }
}
