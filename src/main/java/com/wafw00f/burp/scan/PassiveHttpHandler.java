package com.wafw00f.burp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

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
 * Detección pasiva: observa las respuestas de tráfico PROXY de hosts en scope
 * y aplica las firmas sin enviar ninguna request. La evaluación se descarga a un
 * executor para no frenar el hilo del proxy. No modifica el tráfico.
 */
public final class PassiveHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final Config config;
    private final SignatureEngine engine;
    private final DetectionState state;
    private final IssueReporter reporter;
    private final Executor executor;

    public PassiveHttpHandler(MontoyaApi api, Config config, SignatureEngine engine,
                              DetectionState state, IssueReporter reporter, Executor executor) {
        this.api = api;
        this.config = config;
        this.engine = engine;
        this.state = state;
        this.reporter = reporter;
        this.executor = executor;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            if (config.isPassiveEnabled()
                    && responseReceived.toolSource().isFromTool(ToolType.PROXY, ToolType.REPEATER)) {
                HttpRequest req = responseReceived.initiatingRequest();
                if (req != null) {
                    executor.execute(() -> evaluate(req, responseReceived));
                }
            }
        } catch (RuntimeException ex) {
            api.logging().logToError("[wafw00f] passive handler error: " + ex);
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void evaluate(HttpRequest req, HttpResponseReceived resp) {
        try {
            String url;
            try {
                url = req.url();
            } catch (RuntimeException ex) {
                return;
            }
            if (url == null || !api.scope().isInScope(url)) {
                return;
            }
            String host = req.httpService().host();
            boolean findAll = config.isFindAll();
            if (!findAll && state.hasAny(host)) {
                return; // ya se detectó un WAF para este host
            }
            ResponsePair rp = ResponsePair.passive(new ResponseView(resp));
            List<Signature> matched = engine.identify(rp, findAll);
            if (matched.isEmpty()) {
                return;
            }
            String baseUrl = Urls.base(req.httpService());
            HttpRequestResponse evidence = HttpRequestResponse.httpRequestResponse(req, resp);
            for (Signature s : matched) {
                if (state.shouldReport(host, s.name())) {
                    reporter.report(baseUrl, DetectionResult.fromWafName(s.name(), DetectionMode.PASSIVE,
                            "Passive signature match on in-scope traffic (Proxy/Repeater)", evidence));
                }
            }
        } catch (RuntimeException ex) {
            api.logging().logToError("[wafw00f] passive evaluate error: " + ex);
        }
    }
}
