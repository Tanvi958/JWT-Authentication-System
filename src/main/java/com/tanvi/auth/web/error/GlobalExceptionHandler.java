package com.tanvi.auth.web.error;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ErrorResponse> api(ApiException ex, HttpServletRequest req) {
        return build(ex.status(), ex.code(), ex.getMessage(), req, null);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> validation(MethodArgumentNotValidException ex, HttpServletRequest req) {
        Map<String, String> fields = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors()
                .forEach(fe -> fields.putIfAbsent(fe.getField(), fe.getDefaultMessage()));
        return build(HttpStatus.BAD_REQUEST, "validation_failed", "Some fields are invalid", req, fields);
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<ErrorResponse> malformed(Exception ex, HttpServletRequest req) {
        return build(HttpStatus.BAD_REQUEST, "malformed_request", "The request body or a parameter is malformed", req, null);
    }

    /** Thrown by {@code @PreAuthorize} when the caller lacks a permission. */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> denied(AccessDeniedException ex, HttpServletRequest req) {
        return build(HttpStatus.FORBIDDEN, "access_denied", "You don't have permission to do this", req, null);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> integrity(DataIntegrityViolationException ex, HttpServletRequest req) {
        log.warn("Constraint violation on {}: {}", req.getRequestURI(), ex.getMostSpecificCause().getMessage());
        return build(HttpStatus.CONFLICT, "conflict", "The request conflicts with existing data", req, null);
    }

    private static ResponseEntity<ErrorResponse> build(HttpStatus status, String code, String message,
                                                       HttpServletRequest req, Map<String, String> fields) {
        return ResponseEntity.status(status).body(new ErrorResponse(Instant.now(), status.value(),
                status.getReasonPhrase(), code, message, req.getRequestURI(), fields));
    }
}
