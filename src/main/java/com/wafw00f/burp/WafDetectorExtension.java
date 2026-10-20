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
 * Extension entry point. Burp discovers this class (which implements
 * {@link BurpExtension}) and calls {@link #initialize}.
 *
 * Wiring:
 *  - Automatic PASSIVE detection: {@link PassiveHttpHandler} on in-scope PROXY
 *    traffic, plus {@link ScopeWatcher} which rescans the site map on scope
 *    changes.
 *  - Manual ACTIVE probing: button on the "wafw00f" tab and context menu entry.
 *  - Findings are published as AuditIssue entries under Target -> Issues.
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

        // Single-thread executor for passive work (keeps proxy threads unblocked).
        ExecutorService passiveExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "wafw00f-passive");
            t.setDaemon(true);
            return t;
        });

        WafDetectorTab tab = new WafDetectorTab(api, config, scanner, state);
        api.userInterface().applyThemeToComponent(tab.component());
        api.userInterface().registerSuiteTab("wafw00f", tab.component());
        api.userInterface().registerContextMenuItemsProvider(new WafContextMenu(tab));

        api.http().registerHttpHandler(
                new PassiveHttpHandler(api, config, engine, state, reporter, passiveExecutor));
        api.scope().registerScopeChangeHandler(
                new ScopeWatcher(api, config, engine, state, reporter, passiveExecutor));

        api.extension().registerUnloadingHandler(() -> {
            passiveExecutor.shutdownNow();
            tab.shutdown();
        });

        api.logging().logToOutput("[wafw00f] ready. Passive detection "
                + (config.isPassiveEnabled() ? "ON" : "OFF")
                + ". Use the 'wafw00f' tab or right-click a request to run an active probe.");
    }
}
