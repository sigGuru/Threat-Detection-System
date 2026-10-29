package com.TheSecureSyndicate.threat_detection_backend.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, Object>> handleMaxSizeException(MaxUploadSizeExceededException exc) {
        Map<String, Object> error = new HashMap<>();
        error.put("status", HttpStatus.PAYLOAD_TOO_LARGE.value());
        error.put("error", "Maximum upload size exceeded");
        error.put("message", "The uploaded file exceeds the configured maximum upload limit (100MB). Please select a file under 100MB.");
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE).body(error);
    }
}
