package com.wafw00f.burp.core;

import burp.api.montoya.persistence.Preferences;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runtime configuration, shared between the UI and the detection handlers.
 * Thread-safe. When given {@link Preferences}, the settings are persisted
 * across Burp restarts (at user level, not per project).
 */
public final class Config {

    private static final String KEY_PASSIVE = "wafdetector.passiveEnabled";
    private static final String KEY_FINDALL = "wafdetector.findAll";

    private final Preferences prefs; // may be null (e.g. in tests)
    private final AtomicBoolean passiveEnabled;
    private final AtomicBoolean findAll;

    public Config() {
        this(null);
    }

    public Config(Preferences prefs) {
        this.prefs = prefs;
        this.passiveEnabled = new AtomicBoolean(loadOrDefault(KEY_PASSIVE, true));
        this.findAll = new AtomicBoolean(loadOrDefault(KEY_FINDALL, false));
    }

    private boolean loadOrDefault(String key, boolean def) {
        if (prefs == null) {
            return def;
        }
        try {
            Boolean v = prefs.getBoolean(key);
            return v != null ? v : def;
        } catch (RuntimeException ex) {
            return def;
        }
    }

    private void persist(String key, boolean value) {
        if (prefs == null) {
            return;
        }
        try {
            prefs.setBoolean(key, value);
        } catch (RuntimeException ignore) {
            // best-effort persistence
        }
    }

    public boolean isPassiveEnabled() {
        return passiveEnabled.get();
    }

    public void setPassiveEnabled(boolean value) {
        passiveEnabled.set(value);
        persist(KEY_PASSIVE, value);
    }

    public boolean isFindAll() {
        return findAll.get();
    }

    public void setFindAll(boolean value) {
        findAll.set(value);
        persist(KEY_FINDALL, value);
    }
}
