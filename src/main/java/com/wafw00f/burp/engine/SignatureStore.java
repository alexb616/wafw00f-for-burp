package com.wafw00f.burp.engine;

import com.wafw00f.burp.core.Json;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Loads signatures.json and wafprio.json (resources bundled in the JAR),
 * compiles the regexes and sorts the signatures by priority, mirroring the
 * 'checklist' in wafw00f/main.py: prioritised ones first (in wafprio order),
 * everything else after.
 */
public final class SignatureStore {

    private static final String SIGNATURES_RESOURCE = "/com/wafw00f/burp/signatures.json";
    private static final String PRIORITY_RESOURCE = "/com/wafw00f/burp/wafprio.json";
    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;

    private final List<Signature> signatures;
    private final int patternErrors;

    private SignatureStore(List<Signature> signatures, int patternErrors) {
        this.signatures = signatures;
        this.patternErrors = patternErrors;
    }

    public List<Signature> signatures() {
        return signatures;
    }

    public int size() {
        return signatures.size();
    }

    public int patternErrors() {
        return patternErrors;
    }

    @SuppressWarnings("unchecked")
    public static SignatureStore loadFromResources(Consumer<String> logger) {
        try {
            Map<String, Object> sigRoot = (Map<String, Object>) Json.parse(readResource(SIGNATURES_RESOURCE));
            Map<String, Object> prioRoot = (Map<String, Object>) Json.parse(readResource(PRIORITY_RESOURCE));

            int[] errors = {0};
            Map<String, Signature> ordered = new LinkedHashMap<>(); // slug/insertion order
            Map<String, Signature> byName = new LinkedHashMap<>();

            List<Object> sigs = (List<Object>) sigRoot.get("signatures");
            for (Object el : sigs) {
                Map<String, Object> so = (Map<String, Object>) el;
                String name = (String) so.get("name");
                String slug = (String) so.get("slug");
                Condition root = buildCondition((Map<String, Object>) so.get("match"), errors, slug, logger);
                Signature sig = new Signature(name, slug, root);
                ordered.put(slug, sig);
                byName.put(name, sig);
            }

            // Priority order: wafprio first (in that order), then the rest.
            List<Signature> result = new ArrayList<>();
            Set<String> used = new HashSet<>();
            Object prio = prioRoot.get("priority");
            if (prio instanceof List) {
                for (Object el : (List<Object>) prio) {
                    String name = (String) el;
                    Signature sig = byName.get(name);
                    if (sig != null && used.add(name)) {
                        result.add(sig);
                    }
                }
            }
            for (Signature sig : ordered.values()) {
                if (used.add(sig.name())) {
                    result.add(sig);
                }
            }

            return new SignatureStore(result, errors[0]);
        } catch (IOException | RuntimeException ex) {
            if (logger != null) {
                logger.accept("[wafw00f] ERROR loading signatures: " + ex);
            }
            return new SignatureStore(new ArrayList<>(), 0);
        }
    }

    private static String readResource(String resource) throws IOException {
        try (InputStream in = SignatureStore.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("resource not found: " + resource);
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                bos.write(buf, 0, n);
            }
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    @SuppressWarnings("unchecked")
    private static Condition buildCondition(Map<String, Object> o, int[] errors, String slug, Consumer<String> logger) {
        String op = (String) o.get("op");
        switch (op) {
            case "and":
            case "or": {
                List<Condition> nodes = new ArrayList<>();
                for (Object el : (List<Object>) o.get("nodes")) {
                    nodes.add(buildCondition((Map<String, Object>) el, errors, slug, logger));
                }
                return Condition.group("and".equals(op) ? Condition.Op.AND : Condition.Op.OR, nodes);
            }
            case "not": {
                List<Object> nodes = (List<Object>) o.get("nodes");
                return Condition.not(buildCondition((Map<String, Object>) nodes.get(0), errors, slug, logger));
            }
            case "match":
                return buildMatch(o, errors, slug, logger);
            default:
                throw new IllegalArgumentException("unknown op: " + op);
        }
    }

    private static Condition buildMatch(Map<String, Object> o, int[] errors, String slug, Consumer<String> logger) {
        String type = (String) o.get("type");
        boolean attack = Boolean.TRUE.equals(o.get("attack"));
        switch (type) {
            case "header":
                return Condition.header((String) o.get("name"),
                        compile((String) o.get("pattern"), errors, slug, logger), attack);
            case "cookie":
                return Condition.cookie(compile((String) o.get("pattern"), errors, slug, logger), attack);
            case "content":
                return Condition.content(compile((String) o.get("pattern"), errors, slug, logger), attack);
            case "status":
                return Condition.status(((Number) o.get("status")).intValue(), attack);
            case "reason":
                return Condition.reason((String) o.get("reason"), attack);
            default:
                throw new IllegalArgumentException("unknown match type: " + type);
        }
    }

    private static Pattern compile(String regex, int[] errors, String slug, Consumer<String> logger) {
        try {
            return Pattern.compile(regex, FLAGS);
        } catch (PatternSyntaxException ex) {
            errors[0]++;
            if (logger != null) {
                logger.accept("[wafw00f] WARN regex failed to compile in [" + slug + "]: " + regex
                        + " -> " + ex.getMessage());
            }
            return null; // the condition will act as "never matches"
        }
    }
}
