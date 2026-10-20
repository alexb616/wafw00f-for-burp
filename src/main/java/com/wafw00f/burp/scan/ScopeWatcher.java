package com.wafw00f.burp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scope.ScopeChange;
import burp.api.montoya.scope.ScopeChangeHandler;

import com.wafw00f.burp.core.Config;
import com.wafw00f.burp.core.DetectionMode;
import com.wafw00f.burp.core.DetectionResult;
import com.wafw00f.burp.core.Urls;
import com.wafw00f.burp.engine.ResponsePair;
import com.wafw00f.burp.engine.ResponseView;
import com.wafw00f.burp.engine.Signature;
import com.wafw00f.burp.engine.SignatureEngine;

import java.util.List;
import java.util.concurrent.Executor;

/**
 * When the scope changes (for example, when a target is added), passively
 * rescans the site-map entries already captured for in-scope hosts. This way
 * "when a target is added to scope" the passive detection runs immediately on
 * what has been captured already, without waiting for new traffic or sending
 * any request.
 */
public final class ScopeWatcher implements ScopeChangeHandler {

    private final MontoyaApi api;
    private final Config config;
    private final SignatureEngine engine;
    private final DetectionState state;
    private final IssueReporter reporter;
    private final Executor executor;

    public ScopeWatcher(MontoyaApi api, Config config, SignatureEngine engine,
                        DetectionState state, IssueReporter reporter, Executor executor) {
        this.api = api;
        this.config = config;
        this.engine = engine;
        this.state = state;
        this.reporter = reporter;
        this.executor = executor;
    }

    @Override
    public void scopeChanged(ScopeChange scopeChange) {
        if (!config.isPassiveEnabled()) {
            return;
        }
        executor.execute(this::rescan);
    }

    private void rescan() {
        try {
            boolean findAll = config.isFindAll();
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                if (rr.response() == null) {
                    continue;
                }
                HttpRequest req = rr.request();
                String url;
                try {
                    url = req.url();
                } catch (RuntimeException ex) {
                    continue;
                }
                if (url == null || !api.scope().isInScope(url)) {
                    continue;
                }
                String host = req.httpService().host();
                if (!findAll && state.hasAny(host)) {
                    continue;
                }
                ResponsePair rp = ResponsePair.passive(new ResponseView(rr.response()));
                List<Signature> matched = engine.identify(rp, findAll);
                if (matched.isEmpty()) {
                    continue;
                }
                String baseUrl = Urls.base(req.httpService());
                for (Signature s : matched) {
                    if (state.shouldReport(host, s.name())) {
                        reporter.report(baseUrl, DetectionResult.fromWafName(s.name(), DetectionMode.PASSIVE,
                                "Passive signature match on existing site map entry (scope change)", rr));
                    }
                }
            }
        } catch (RuntimeException ex) {
            api.logging().logToError("[wafw00f] scope rescan error: " + ex);
        }
    }
}
