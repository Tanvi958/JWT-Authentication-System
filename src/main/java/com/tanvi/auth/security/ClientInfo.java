package com.tanvi.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;

/**
 * The caller's IP address and browser, recorded on sessions and security events.
 * Behind a proxy, {@code server.forward-headers-strategy=framework} makes {@code getRemoteAddr()} the real client.
 */
public record ClientInfo(String ip, String userAgent) {

    public static ClientInfo from(HttpServletRequest request) {
        String ua = request.getHeader(HttpHeaders.USER_AGENT);
        if (ua != null && ua.length() > 255) ua = ua.substring(0, 255);
        return new ClientInfo(request.getRemoteAddr(), ua);
    }

    /** "Chrome on Windows", "Firefox on Android", "curl"… good enough for a session list. */
    public static String describe(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) return "Unknown device";
        String ua = userAgent.toLowerCase();
        String browser = ua.contains("edg/") ? "Edge"
                : ua.contains("opr/") || ua.contains("opera") ? "Opera"
                : ua.contains("chrome/") ? "Chrome"
                : ua.contains("firefox/") ? "Firefox"
                : ua.contains("safari/") ? "Safari"
                : ua.startsWith("curl") ? "curl"
                : ua.contains("postman") ? "Postman"
                : ua.contains("mockmvc") ? "Test client"
                : "Browser";
        String os = ua.contains("windows") ? "Windows"
                : ua.contains("android") ? "Android"
                : ua.contains("iphone") || ua.contains("ipad") ? "iOS"
                : ua.contains("mac os") ? "macOS"
                : ua.contains("linux") ? "Linux"
                : null;
        return os == null ? browser : browser + " on " + os;
    }
}
