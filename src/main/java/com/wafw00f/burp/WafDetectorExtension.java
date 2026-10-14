package com.wafw00f.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.wafw00f.burp.core.Config;
import com.wafw00f.burp.engine.SignatureEngine;
import com.wafw00f.burp.scan.ActiveScanner;
import com.wafw00f.burp.scan.DetectionState;
import com.wafw00f.burp.scan.IssueReporter;
import com.wafw00f.burp.scan.PassiveHttpHandler;
import com.wafw00f.burp.scan.ScopeWatcher;
import com.wafw00f.burp.ui.WafContextMenu;
import com.wafw00f.burp.ui.WafDetectorTab;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Punto de entrada de la extensión. Burp descubre esta clase (implementa
 * {@link BurpExtension}) y llama a {@link #initialize}.
 *
 * Cableado:
 *  - Detección PASIVA automática: {@link PassiveHttpHandler} sobre tráfico PROXY
 *    en scope + {@link ScopeWatcher} que repasa el site map al cambiar el scope.
 *  - Sondeo ACTIVO manual: botón en la pestaña "wafw00f" y menú contextual.
 *  - Los hallazgos se publican como AuditIssue en Target -> Issues.
 */
public final class WafDetectorExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("wafw00f for Burp");

        Config config = new Config(api.persistence().preferences());

        SignatureEngine engine = SignatureEngine.create(api.logging()::logToOutput);
        api.logging().logToOutput("[wafw00f] loaded " + engine.signatureCount()
                + " signatures (" + engine.patternErrors() + " regex compile errors).");

        DetectionState state = new DetectionState();
        IssueReporter reporter = new IssueReporter(api);
        ActiveScanner scanner = new ActiveScanner(api, engine, reporter, state);

        // Executor de un hilo para el trabajo pasivo (no bloquea los hilos del proxy).
        ExecutorService passiveExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "wafw00f-passive");
            t.setDaemon(true);
            return t;
        });

        WafDetectorTab tab = new WafDetectorTab(api, config, scanner, state);
        api.userInterface().registerSuiteTab("wafw00f", tab.component());
        api.userInterface().registerContextMenuItemsProvider(new WafContextMenu(tab));

        api.http().registerHttpHandler(
                new PassiveHttpHandler(api, config, engine, state, reporter, passiveExecutor));
        api.scope().registerScopeChangeHandler(
                new ScopeWatcher(api, config, engine, state, reporter, passiveExecutor));

        api.extension().registerUnloadingHandler(passiveExecutor::shutdownNow);

        api.logging().logToOutput("[wafw00f] ready. Passive detection "
                + (config.isPassiveEnabled() ? "ON" : "OFF")
                + ". Use the 'wafw00f' tab or right-click a request to run an active probe.");
    }
}
