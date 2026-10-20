package com.wafw00f.burp.core;

import java.security.SecureRandom;

/**
 * Attack payloads and random parameter names, matching wafw00f (see
 * wafw00f/main.py: xsstring, sqlistring, lfistring, rcestring, xxestring and
 * create_random_param_name).
 */
public final class Payloads {

    public static final String XSS  = "<script>alert(\"XSS\");</script>";
    public static final String SQLI = "UNION SELECT ALL FROM information_schema AND \" or SLEEP(5) or \"";
    public static final String LFI  = "../../etc/passwd";
    public static final String RCE  = "/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com";
    public static final String XXE  = "<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><pwn>&hack;</pwn>";

    private static final SecureRandom RNG = new SecureRandom();
    private static final String ALPHA = "abcdefghijklmnopqrstuvwxyz";

    private Payloads() {
    }

    /** Random parameter name of fixed length (wafw00f uses 8). */
    public static String randomParam(int size) {
        StringBuilder sb = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            sb.append(ALPHA.charAt(RNG.nextInt(ALPHA.length())));
        }
        return sb.toString();
    }

    public static String randomParam() {
        return randomParam(8);
    }
}
