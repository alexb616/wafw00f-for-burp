package com.wafw00f.burp.scan;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.wafw00f.burp.core.DetectionMode;
import com.wafw00f.burp.core.DetectionResult;
import com.wafw00f.burp.http.ActiveProber;

/**
 * Behaviour-based generic detection, ported from genericdetect() in
 * wafw00f/main.py. Used as a fallback when no signature matches: compares the
 * normal response with the attack responses (status code, Server header and
 * no-User-Agent response) to infer the presence of a WAF.
 */
public final class GenericDetector {

    private static final String[] REASONS = {
            "Blocking is being done at connection/packet level.",
            "The server header is different when an attack is detected.",
            "The server returns a different response code when an attack string is used.",
            "It closed the connection for a normal request.",
            "The response was different when the request wasn't made from a browser."
    };

    private GenericDetector() {
    }

    private static int status(HttpRequestResponse rr) {
        return (rr != null && rr.response() != null) ? (rr.response().statusCode() & 0xFFFF) : -1;
    }

    private static String server(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) {
            return "";
        }
        String v = rr.response().headerValue("Server");
        return v == null ? "" : v;
    }

    public static DetectionResult detect(ActiveProber prober, HttpRequest base,
                                         HttpRequestResponse normalRR, HttpRequestResponse attackRR) {
        int normalStatus = status(normalRR);
        if (normalStatus < 0) {
            // The normal request did not reach the server: connection/packet-level blocking.
            return DetectionResult.generic(DetectionMode.ACTIVE, REASONS[0], normalRR);
        }

        // 1) Response without the User-Agent header.
        HttpRequestResponse noUaRR = prober.send(prober.withoutUserAgent(base));
        int noUaStatus = status(noUaRR);
        if (noUaStatus >= 0 && normalStatus != noUaStatus) {
            return DetectionResult.generic(DetectionMode.ACTIVE,
                    REASONS[4] + " Normal status=" + normalStatus + ", no-User-Agent status=" + noUaStatus,
                    noUaRR);
        }

        // 2) XSS: status-code change.
        HttpRequestResponse xssRR = prober.send(prober.xssAttack(base));
        if (status(xssRR) < 0) {
            return DetectionResult.generic(DetectionMode.ACTIVE, REASONS[0], xssRR);
        }
        if (normalStatus != status(xssRR)) {
            return DetectionResult.generic(DetectionMode.ACTIVE,
                    REASONS[2] + " Normal status=" + normalStatus + ", XSS status=" + status(xssRR), xssRR);
        }

        // 3) LFI (in path): status-code change.
        HttpRequestResponse lfiRR = prober.send(prober.lfiAttack(base));
        if (status(lfiRR) < 0) {
            return DetectionResult.generic(DetectionMode.ACTIVE, REASONS[0], lfiRR);
        }
        if (normalStatus != status(lfiRR)) {
            return DetectionResult.generic(DetectionMode.ACTIVE,
                    REASONS[2] + " Normal status=" + normalStatus + ", LFI status=" + status(lfiRR), lfiRR);
        }

        // 4) SQLi: status-code change.
        HttpRequestResponse sqliRR = prober.send(prober.sqliAttack(base));
        if (status(sqliRR) < 0) {
            return DetectionResult.generic(DetectionMode.ACTIVE, REASONS[0], sqliRR);
        }
        if (normalStatus != status(sqliRR)) {
            return DetectionResult.generic(DetectionMode.ACTIVE,
                    REASONS[2] + " Normal status=" + normalStatus + ", SQLi status=" + status(sqliRR), sqliRR);
        }

        // 5) Server header differs between normal and attack responses.
        String normalServer = server(normalRR);
        String attackServer = server(attackRR);
        if (!attackServer.equals(normalServer)) {
            return DetectionResult.generic(DetectionMode.ACTIVE,
                    REASONS[1] + " Normal Server=\"" + normalServer + "\", attack Server=\"" + attackServer + "\"",
                    attackRR != null ? attackRR : normalRR);
        }

        return null; // no generic indicators
    }
}
