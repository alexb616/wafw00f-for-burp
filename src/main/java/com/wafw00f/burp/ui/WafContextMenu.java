package com.wafw00f.burp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Adds "wafw00f: active probe this host" to the context menu on any
 * request/response (Proxy history, Repeater, Target, etc.).
 */
public final class WafContextMenu implements ContextMenuItemsProvider {

    private final WafDetectorTab tab;

    public WafContextMenu(WafDetectorTab tab) {
        this.tab = tab;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        String url = extractUrl(event);
        if (url == null) {
            return Collections.emptyList();
        }
        JMenuItem item = new JMenuItem("wafw00f: active probe this host");
        final String target = url;
        item.addActionListener(e -> tab.runActiveScan(target));
        return List.of(item);
    }

    private String extractUrl(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) {
            try {
                return selected.get(0).request().url();
            } catch (RuntimeException ignore) {
                // malformed request: try the other path
            }
        }
        Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
        if (editor.isPresent()) {
            try {
                return editor.get().requestResponse().request().url();
            } catch (RuntimeException ignore) {
                // no usable URL
            }
        }
        return null;
    }
}
