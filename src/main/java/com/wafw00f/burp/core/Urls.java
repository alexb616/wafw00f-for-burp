package com.wafw00f.burp.core;

import burp.api.montoya.http.HttpService;

/** Utilidades de URL. */
public final class Urls {

    private Urls() {
    }

    /** URL raíz "scheme://host[:port]" para asociar el issue al nodo del target. */
    public static String base(HttpService service) {
        String scheme = service.secure() ? "https" : "http";
        int port = service.port();
        boolean standard = (service.secure() && port == 443) || (!service.secure() && port == 80);
        return scheme + "://" + service.host() + (standard ? "" : ":" + port);
    }
}
