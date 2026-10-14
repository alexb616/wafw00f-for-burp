package com.wafw00f.burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.wafw00f.burp.core.Payloads;

/**
 * Construye y envía las requests del sondeo activo, replicando wafw00f:
 * cabeceras por defecto de navegador, request normal, centralAttack
 * (XSS+SQLi+LFI en parámetros GET con nombres aleatorios) y las variantes
 * individuales que usa la detección genérica. Sigue redirecciones (como
 * wafw00f con allow_redirects=True).
 */
public final class ActiveProber {

    // wafw00f/lib/evillib.py def_headers
    private static final String UA =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0";
    private static final String ACCEPT =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3";

    private final MontoyaApi api;
    private final RequestOptions options;

    public ActiveProber(MontoyaApi api) {
        this.api = api;
        this.options = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.ALWAYS);
    }

    /** Request base (GET al target) con las cabeceras de navegador de wafw00f. */
    public HttpRequest base(String url) {
        return HttpRequest.httpRequestFromUrl(url)
                .withHeader("User-Agent", UA)
                .withHeader("Accept", ACCEPT)
                .withHeader("Accept-Language", "en-US,en;q=0.5")
                .withHeader("Upgrade-Insecure-Requests", "1")
                .withHeader("DNT", "1");
    }

    public HttpRequestResponse send(HttpRequest request) {
        return api.http().sendRequest(request, options);
    }

    /** centralAttack: XSS + SQLi + LFI en tres parámetros GET aleatorios. */
    public HttpRequest centralAttack(HttpRequest base) {
        return base.withAddedParameters(
                HttpParameter.urlParameter(Payloads.randomParam(), Payloads.XSS),
                HttpParameter.urlParameter(Payloads.randomParam(), Payloads.SQLI),
                HttpParameter.urlParameter(Payloads.randomParam(), Payloads.LFI));
    }

    public HttpRequest xssAttack(HttpRequest base) {
        return base.withAddedParameters(HttpParameter.urlParameter(Payloads.randomParam(), Payloads.XSS));
    }

    public HttpRequest sqliAttack(HttpRequest base) {
        return base.withAddedParameters(HttpParameter.urlParameter(Payloads.randomParam(), Payloads.SQLI));
    }

    /** lfiAttack: wafw00f lo inyecta en el PATH (path + '../../etc/passwd'). */
    public HttpRequest lfiAttack(HttpRequest base) {
        String path = base.pathWithoutQuery();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (!path.endsWith("/")) {
            path = path + "/";
        }
        return base.withPath(path + Payloads.LFI);
    }

    public HttpRequest withoutUserAgent(HttpRequest base) {
        return base.withRemovedHeader("User-Agent");
    }
}
