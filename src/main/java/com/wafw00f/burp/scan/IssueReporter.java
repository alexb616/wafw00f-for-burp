package com.wafw00f.burp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import com.wafw00f.burp.core.DetectionResult;

/**
 * Builds an informational {@link AuditIssue} and adds it to the site map so it
 * appears under Target -> Issues for the corresponding host.
 */
public final class IssueReporter {

    private static final String BACKGROUND =
            "This informational issue is raised by the wafw00f for Burp extension (a native Burp port of "
            + "<b>wafw00f</b>). It fingerprints Web Application Firewalls and CDNs/security solutions by "
            + "analysing HTTP responses: server/cookie/header markers and, in active mode, the behaviour of "
            + "the target against probe requests (XSS/SQLi/LFI). Knowing the WAF in front of an application "
            + "helps tailor evasion and testing. Detection is best-effort and can yield false positives or "
            + "negatives.";

    private final MontoyaApi api;

    public IssueReporter(MontoyaApi api) {
        this.api = api;
    }

    public void report(String baseUrl, DetectionResult r) {
        String name;
        AuditIssueConfidence confidence;
        StringBuilder detail = new StringBuilder();

        if (r.isNone()) {
            name = "No WAF detected (active probe)";
            confidence = AuditIssueConfidence.CERTAIN;
            detail.append("An active probe (a normal request plus XSS/SQLi/LFI attack requests) was ")
                    .append("performed against this host and <b>no known WAF signature</b> and no generic ")
                    .append("WAF behaviour were detected.<br><br>");
            detail.append("<b>Detection mode:</b> ").append(r.mode().label()).append("<br>");
            if (r.evidence() != null && !r.evidence().isEmpty()) {
                detail.append("<b>Note:</b> ").append(escape(r.evidence())).append("<br>");
            }
        } else {
            name = r.isGeneric()
                    ? "WAF / security solution detected (generic)"
                    : "WAF detected: " + escape(r.firewall());
            confidence = r.isGeneric()
                    ? AuditIssueConfidence.TENTATIVE
                    : AuditIssueConfidence.CERTAIN;
            detail.append("A Web Application Firewall / security solution was identified for this host.<br><br>");
            detail.append("<b>Firewall:</b> ").append(escape(r.firewall())).append("<br>");
            detail.append("<b>Manufacturer:</b> ").append(escape(r.manufacturer())).append("<br>");
            detail.append("<b>Detection mode:</b> ").append(r.mode().label()).append("<br>");
            if (r.evidence() != null && !r.evidence().isEmpty()) {
                detail.append("<b>Evidence:</b> ").append(escape(r.evidence())).append("<br>");
            }
        }

        AuditIssue issue;
        HttpRequestResponse ev = r.evidenceExchange();
        if (ev != null) {
            issue = AuditIssue.auditIssue(name, detail.toString(), null, baseUrl,
                    AuditIssueSeverity.INFORMATION, confidence, BACKGROUND, null,
                    AuditIssueSeverity.INFORMATION, ev);
        } else {
            issue = AuditIssue.auditIssue(name, detail.toString(), null, baseUrl,
                    AuditIssueSeverity.INFORMATION, confidence, BACKGROUND, null,
                    AuditIssueSeverity.INFORMATION);
        }
        api.siteMap().add(issue);
        api.logging().logToOutput("[wafw00f] " + r.mode().label() + " @ " + baseUrl
                + " -> " + r.wafName());
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
