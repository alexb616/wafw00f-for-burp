package com.wafw00f.burp.engine;

/**
 * A WAF signature: name "Firewall (Manufacturer)", slug (original file name)
 * and the condition tree. {@link #matches} is wafw00f's is_waf(self).
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
