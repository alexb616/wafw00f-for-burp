package com.wafw00f.burp.core;

import burp.api.montoya.http.HttpService;

/** URL utilities. */
public final class Urls {

    private Urls() {
    }

    /** Root URL "scheme://host[:port]" used to attach the issue to the target node. */
    public static String base(HttpService service) {
        String scheme = service.secure() ? "https" : "http";
        int port = service.port();
        boolean standard = (service.secure() && port == 443) || (!service.secure() && port == 80);
        return scheme + "://" + service.host() + (standard ? "" : ":" + port);
    }
}
