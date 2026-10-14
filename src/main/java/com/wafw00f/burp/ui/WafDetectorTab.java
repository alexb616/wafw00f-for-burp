package com.wafw00f.burp.ui;

import burp.api.montoya.MontoyaApi;

import com.wafw00f.burp.core.Config;
import com.wafw00f.burp.core.DetectionResult;
import com.wafw00f.burp.scan.ActiveScanner;
import com.wafw00f.burp.scan.DetectionState;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Pestaña de la extensión: activar/desactivar la detección pasiva, lanzar el
 * sondeo activo manual contra una URL y ver la tabla de hallazgos y un log.
 */
public final class WafDetectorTab {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final MontoyaApi api;
    private final Config config;
    private final ActiveScanner scanner;
    private final DetectionState state;
    private final ExecutorService scanExecutor;

    private final JPanel root = new JPanel(new BorderLayout(8, 8));
    private final DefaultTableModel tableModel;
    private final JTextArea logArea = new JTextArea(8, 80);
    private final JTextField targetField = new JTextField(40);
    private final JButton scanButton = new JButton("Run active probe");

    public WafDetectorTab(MontoyaApi api, Config config, ActiveScanner scanner, DetectionState state) {
        this.api = api;
        this.config = config;
        this.scanner = scanner;
        this.state = state;
        this.scanExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "wafw00f-active");
            t.setDaemon(true);
            return t;
        });
        this.tableModel = new DefaultTableModel(
                new Object[]{"Time", "Target", "Firewall", "Manufacturer", "Mode", "Evidence"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        build();
    }

    private void build() {
        root.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // --- controles ---
        JPanel controls = new JPanel();
        controls.setLayout(new BoxLayout(controls, BoxLayout.Y_AXIS));

        JPanel optionsRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 4));
        JCheckBox passiveBox = new JCheckBox("Enable passive WAF detection (in-scope traffic)", config.isPassiveEnabled());
        passiveBox.addActionListener(e -> {
            config.setPassiveEnabled(passiveBox.isSelected());
            appendLog("Passive detection " + (passiveBox.isSelected() ? "ENABLED" : "DISABLED"));
        });
        JCheckBox findAllBox = new JCheckBox("Find all (don't stop at first match)", config.isFindAll());
        findAllBox.addActionListener(e -> {
            config.setFindAll(findAllBox.isSelected());
            appendLog("Find-all " + (findAllBox.isSelected() ? "ENABLED" : "DISABLED"));
        });
        optionsRow.add(passiveBox);
        optionsRow.add(findAllBox);

        JPanel scanRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        scanRow.add(new JLabel("Target URL:"));
        scanRow.add(targetField);
        scanRow.add(scanButton);
        JButton clearButton = new JButton("Clear table");
        JButton resetButton = new JButton("Reset detections");
        scanRow.add(clearButton);
        scanRow.add(resetButton);

        scanButton.addActionListener(e -> runActiveScan(targetField.getText()));
        targetField.addActionListener(e -> runActiveScan(targetField.getText()));
        clearButton.addActionListener(e -> tableModel.setRowCount(0));
        resetButton.addActionListener(e -> {
            state.resetAll();
            appendLog("Detection memory reset: hosts will be re-evaluated.");
        });

        controls.add(optionsRow);
        controls.add(scanRow);

        // --- tabla + log ---
        JTable table = new JTable(tableModel);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Detected WAFs"));

        logArea.setEditable(false);
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Log"));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, logScroll);
        split.setResizeWeight(0.7);
        split.setPreferredSize(new Dimension(900, 500));

        root.add(controls, BorderLayout.NORTH);
        root.add(split, BorderLayout.CENTER);
    }

    public Component component() {
        return root;
    }

    /** Lanza un sondeo activo en segundo plano (desde el botón o el menú contextual). */
    public void runActiveScan(String rawUrl) {
        final String url = normalize(rawUrl);
        if (url == null) {
            appendLog("Provide a target URL first.");
            return;
        }
        SwingUtilities.invokeLater(() -> scanButton.setEnabled(false));
        appendLog("Active probe starting: " + url);
        scanExecutor.execute(() -> {
            try {
                List<DetectionResult> results = scanner.scan(url, config.isFindAll());
                SwingUtilities.invokeLater(() -> publish(url, results));
            } catch (RuntimeException ex) {
                api.logging().logToError("[wafw00f] active scan error: " + ex);
                SwingUtilities.invokeLater(() -> appendLog("Error scanning " + url + ": " + ex));
            } finally {
                SwingUtilities.invokeLater(() -> scanButton.setEnabled(true));
            }
        });
    }

    private void publish(String url, List<DetectionResult> results) {
        if (results == null) {
            appendLog("Target did not respond (down/unreachable): " + url);
            return;
        }
        if (results.isEmpty()) {
            appendLog("No WAF detected on " + url);
            return;
        }
        for (DetectionResult r : results) {
            tableModel.addRow(new Object[]{
                    LocalTime.now().format(TIME), url, r.firewall(), r.manufacturer(),
                    r.mode().label(), r.evidence()});
            if (r.isNone()) {
                appendLog("No WAF detected on " + url + " (active probe)");
            } else {
                appendLog("Detected " + r.wafName() + " on " + url + " [" + r.mode().label() + "]");
            }
        }
    }

    private void appendLog(String message) {
        Runnable r = () -> {
            logArea.append("[" + LocalTime.now().format(TIME) + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        };
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeLater(r);
        }
    }

    private static String normalize(String raw) {
        if (raw == null) {
            return null;
        }
        String url = raw.trim();
        if (url.isEmpty()) {
            return null;
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url; // wafw00f asume https si falta el esquema
        }
        return url;
    }
}
