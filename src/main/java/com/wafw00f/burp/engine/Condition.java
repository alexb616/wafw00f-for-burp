package com.wafw00f.burp.engine;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Nodo del árbol booleano de una firma. Replica las primitivas de wafw00f
 * (matchHeader / matchCookie / matchContent / matchStatus / matchReason) y su
 * composición (OR entre checks, AND dentro de check_schema_*).
 *
 * Las regex se compilan una sola vez, con CASE_INSENSITIVE (wafw00f usa re.I)
 * y DOTALL deliberadamente DESACTIVADO, para que '.' no cruce saltos de línea,
 * igual que el re.search por defecto de Python.
 */
public final class Condition {

    public enum Op { MATCH, AND, OR, NOT }

    public enum MType { HEADER, COOKIE, CONTENT, STATUS, REASON }

    private final Op op;

    // AND / OR / NOT
    private final List<Condition> nodes;

    // MATCH
    private final MType type;
    private final String headerName;
    private final Pattern pattern;   // header/cookie/content; null si la regex no compiló
    private final int status;
    private final String reason;
    private final boolean attack;

    private Condition(Op op, List<Condition> nodes, MType type, String headerName,
                      Pattern pattern, int status, String reason, boolean attack) {
        this.op = op;
        this.nodes = nodes;
        this.type = type;
        this.headerName = headerName;
        this.pattern = pattern;
        this.status = status;
        this.reason = reason;
        this.attack = attack;
    }

    // ---- factorías ----

    public static Condition group(Op op, List<Condition> nodes) {
        return new Condition(op, nodes, null, null, null, 0, null, false);
    }

    public static Condition not(Condition inner) {
        return new Condition(Op.NOT, List.of(inner), null, null, null, 0, null, false);
    }

    public static Condition header(String name, Pattern pattern, boolean attack) {
        return new Condition(Op.MATCH, null, MType.HEADER, name, pattern, 0, null, attack);
    }

    public static Condition cookie(Pattern pattern, boolean attack) {
        return new Condition(Op.MATCH, null, MType.COOKIE, "Set-Cookie", pattern, 0, null, attack);
    }

    public static Condition content(Pattern pattern, boolean attack) {
        return new Condition(Op.MATCH, null, MType.CONTENT, null, pattern, 0, null, attack);
    }

    public static Condition status(int code, boolean attack) {
        return new Condition(Op.MATCH, null, MType.STATUS, null, null, code, null, attack);
    }

    public static Condition reason(String phrase, boolean attack) {
        return new Condition(Op.MATCH, null, MType.REASON, null, null, 0, phrase, attack);
    }

    // ---- evaluación ----

    public boolean eval(ResponsePair rp) {
        switch (op) {
            case AND:
                for (Condition c : nodes) {
                    if (!c.eval(rp)) {
                        return false;
                    }
                }
                return true;
            case OR:
                for (Condition c : nodes) {
                    if (c.eval(rp)) {
                        return true;
                    }
                }
                return false;
            case NOT:
                return !nodes.get(0).eval(rp);
            case MATCH:
            default:
                return evalMatch(rp);
        }
    }

    private boolean evalMatch(ResponsePair rp) {
        ResponseView r = rp.pick(attack);
        if (!r.present()) {
            return false;
        }
        switch (type) {
            case HEADER:
            case COOKIE:
                if (pattern == null) {
                    return false;
                }
                for (String value : r.headerValues(headerName)) {
                    if (value != null && pattern.matcher(value).find()) {
                        return true;
                    }
                }
                return false;
            case CONTENT:
                if (pattern == null) {
                    return false;
                }
                String body = r.body();
                return !body.isEmpty() && pattern.matcher(body).find();
            case STATUS:
                return r.statusCode() == status;
            case REASON:
                String phrase = r.reasonPhrase();
                return phrase != null && phrase.equals(reason);
            default:
                return false;
        }
    }
}
