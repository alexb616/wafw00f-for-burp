package com.wafw00f.burp.engine;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight view over an {@link HttpResponse} used by the signature checks.
 * Caches the body as a String (content signatures scan it several times). A
 * view with no response ({@link #present()} == false) makes every check fail,
 * matching wafw00f's behaviour when the response is None.
 */
public final class ResponseView {

    private final HttpResponse response;
    private String bodyCache;

    public ResponseView(HttpResponse response) {
        this.response = response;
    }

    public boolean present() {
        return response != null;
    }

    public int statusCode() {
        return response == null ? -1 : (response.statusCode() & 0xFFFF);
    }

    public String reasonPhrase() {
        return response == null ? null : response.reasonPhrase();
    }

    /** All header values whose name matches (case-insensitive). */
    public List<String> headerValues(String name) {
        List<String> out = new ArrayList<>();
        if (response == null) {
            return out;
        }
        for (HttpHeader h : response.headers()) {
            if (h.name().equalsIgnoreCase(name)) {
                out.add(h.value());
            }
        }
        return out;
    }

    public String body() {
        if (response == null) {
            return "";
        }
        if (bodyCache == null) {
            String b;
            try {
                b = response.bodyToString();
            } catch (RuntimeException ex) {
                b = "";
            }
            bodyCache = (b == null) ? "" : b;
        }
        return bodyCache;
    }
}
