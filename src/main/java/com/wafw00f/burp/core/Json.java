package com.wafw00f.burp.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser JSON mínimo y sin dependencias (recursive descent), suficiente para
 * leer signatures.json / wafprio.json. Devuelve un grafo de objetos:
 * {@link Map} (objeto), {@link List} (array), {@link String}, {@link Long} o
 * {@link Double} (número), {@link Boolean} y {@code null}.
 *
 * Se evita así empaquetar una librería externa (gson): el JAR queda limpio.
 */
public final class Json {

    private final String s;
    private int i;

    private Json(String s) {
        this.s = s;
    }

    public static Object parse(String text) {
        Json p = new Json(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i < p.s.length()) {
            throw p.err("end of input");
        }
        return v;
    }

    private Object value() {
        char c = s.charAt(i);
        switch (c) {
            case '{':
                return object();
            case '[':
                return array();
            case '"':
                return string();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return number();
        }
    }

    private Map<String, Object> object() {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        i++; // consume '{'
        ws();
        if (s.charAt(i) == '}') {
            i++;
            return m;
        }
        while (true) {
            ws();
            String key = string();
            ws();
            if (s.charAt(i) != ':') {
                throw err("':'");
            }
            i++;
            ws();
            m.put(key, value());
            ws();
            char c = s.charAt(i++);
            if (c == '}') {
                break;
            }
            if (c != ',') {
                throw err("',' or '}'");
            }
        }
        return m;
    }

    private List<Object> array() {
        ArrayList<Object> a = new ArrayList<>();
        i++; // consume '['
        ws();
        if (s.charAt(i) == ']') {
            i++;
            return a;
        }
        while (true) {
            ws();
            a.add(value());
            ws();
            char c = s.charAt(i++);
            if (c == ']') {
                break;
            }
            if (c != ',') {
                throw err("',' or ']'");
            }
        }
        return a;
    }

    private String string() {
        if (s.charAt(i) != '"') {
            throw err("'\"'");
        }
        i++;
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = s.charAt(i++);
            if (c == '"') {
                break;
            }
            if (c == '\\') {
                char e = s.charAt(i++);
                switch (e) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case '/':  sb.append('/');  break;
                    case 'b':  sb.append('\b'); break;
                    case 'f':  sb.append('\f'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    case 'u':
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default:
                        throw err("valid escape");
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private Object number() {
        int start = i;
        while (i < s.length()) {
            char c = s.charAt(i);
            if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
                i++;
            } else {
                break;
            }
        }
        String num = s.substring(start, i);
        if (num.isEmpty()) {
            throw err("number");
        }
        if (num.indexOf('.') >= 0 || num.indexOf('e') >= 0 || num.indexOf('E') >= 0) {
            return Double.parseDouble(num);
        }
        return Long.parseLong(num);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                i++;
            } else {
                break;
            }
        }
    }

    private void expect(String literal) {
        if (!s.startsWith(literal, i)) {
            throw err("'" + literal + "'");
        }
        i += literal.length();
    }

    private IllegalStateException err(String expected) {
        return new IllegalStateException("JSON parse error at index " + i + ", expected " + expected);
    }
}
