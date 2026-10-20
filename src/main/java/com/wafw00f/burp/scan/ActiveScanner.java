package com.wafw00f.burp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.wafw00f.burp.core.DetectionMode;
import com.wafw00f.burp.core.DetectionResult;
import com.wafw00f.burp.core.Urls;
import com.wafw00f.burp.engine.ResponsePair;
import com.wafw00f.burp.engine.ResponseView;
import com.wafw00f.burp.engine.Signature;
import com.wafw00f.burp.engine.SignatureEngine;
import com.wafw00f.burp.http.ActiveProber;

import java.util.ArrayList;
import java.util.List;

/**
 * Full active probe for a host, mirroring wafw00f's identwaf()+genericdetect()
 * flow: sends the normal request and the centralAttack, evaluates the
 * signatures and, if none match (or in findAll mode), runs the generic
 * detection. Each new finding is reported as an AuditIssue; the list is also
 * returned so the UI can show it.
 */
public final class ActiveScanner {

    private final MontoyaApi api;
    private final SignatureEngine engine;
    private final IssueReporter reporter;
    private final DetectionState state;

    public ActiveScanner(MontoyaApi api, SignatureEngine engine, IssueReporter reporter, DetectionState state) {
        this.api = api;
        this.engine = engine;
        this.reporter = reporter;
        this.state = state;
    }

    /**
     * @return list of detected WAFs (empty = nothing detected); {@code null} if
     *         the site did not respond to the normal request (down or unreachable).
     */
    public List<DetectionResult> scan(String url, boolean findAll) {
        ActiveProber prober = new ActiveProber(api);

        HttpRequest base;
        try {
            base = prober.base(url);
        } catch (RuntimeException ex) {
            api.logging().logToError("[wafw00f] invalid URL '" + url + "': " + ex);
            return null;
        }

        HttpRequestResponse normalRR = prober.send(base);
        if (normalRR == null || normalRR.response() == null) {
            return null; // site down / unreachable
        }

        HttpRequestResponse attackRR = prober.send(prober.centralAttack(base));

        ResponseView normalView = new ResponseView(normalRR.response());
        ResponseView attackView = new ResponseView(attackRR != null ? attackRR.response() : null);
        ResponsePair rp = new ResponsePair(normalView, attackView);

        String host = normalRR.request().httpService().host();
        String baseUrl = Urls.base(normalRR.request().httpService());

        List<DetectionResult> results = new ArrayList<>();
        for (Signature s : engine.identify(rp, findAll)) {
            DetectionResult dr = DetectionResult.fromWafName(s.name(), DetectionMode.ACTIVE,
                    "Signature match on active probe", attackRR != null ? attackRR : normalRR);
            results.add(dr);
            if (state.shouldReport(host, dr.wafName())) {
                reporter.report(baseUrl, dr);
            }
        }

        if (results.isEmpty() || findAll) {
            DetectionResult generic = GenericDetector.detect(prober, base, normalRR, attackRR);
            if (generic != null) {
                results.add(generic);
                if (state.shouldReport(host, generic.wafName())) {
                    reporter.report(baseUrl, generic);
                }
            }
        }

        // Nothing detected after the active probe: explicitly report "No WAF detected".
        if (results.isEmpty()) {
            DetectionResult none = DetectionResult.none(DetectionMode.ACTIVE,
                    "Active probe performed; no WAF signature or generic indicator matched.", normalRR);
            results.add(none);
            if (!state.hasAny(host) && state.shouldReport(host, "::none::")) {
                reporter.report(baseUrl, none);
            }
        }

        return results;
    }
}
