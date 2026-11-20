package com.tanvi.auth.web.error;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.stream.Collectors;

/** The JSON body of every error, from controllers and from security filters alike. */
public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String code,
        String message,
        String path,
        Map<String, String> fieldErrors
) {

    /**
     * Writes an error straight to the servlet response. Used by filters, which run before Spring MVC
     * and so can't rely on its JSON converters.
     */
    public static void write(HttpServletResponse res, int status, String error, String code, String message,
                             String path) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        res.getWriter().write("{\"timestamp\":\"" + Instant.now() + "\",\"status\":" + status
                + ",\"error\":" + quote(error) + ",\"code\":" + quote(code) + ",\"message\":" + quote(message)
                + ",\"path\":" + quote(path) + ",\"fieldErrors\":null}");
    }

    static String quote(String s) {
        if (s == null) return "null";
        return s.chars().mapToObj(c -> switch (c) {
            case '"' -> "\\\"";
            case '\\' -> "\\\\";
            case '\n' -> "\\n";
            case '\r' -> "\\r";
            case '\t' -> "\\t";
            default -> c < 0x20 ? String.format("\\u%04x", c) : String.valueOf((char) c);
        }).collect(Collectors.joining("", "\"", "\""));
    }
}
