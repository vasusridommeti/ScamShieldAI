package com.scamshield.controller;

import com.scamshield.service.ScamAnalysisService;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** REST endpoints. The analysed message is never logged or stored. */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "${scamshield.allowed-origins}")
public class AnalysisController {

    public record AnalyzeRequest(String message) { }

    private final ScamAnalysisService service;

    public AnalysisController(ScamAnalysisService service) {
        this.service = service;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok", "engine", "rule-based scam-awareness engine");
    }

    @PostMapping("/analyze")
    public ResponseEntity<?> analyze(@RequestBody(required = false) AnalyzeRequest request) {
        String message = request == null ? null : request.message();
        if (message == null || message.trim().isEmpty()) {
            return error("Please provide a non-empty \"message\".");
        }
        String trimmed = message.trim();
        if (trimmed.length() > ScamAnalysisService.MAX_INPUT) {
            return error("The message is longer than " + ScamAnalysisService.MAX_INPUT + " characters.");
        }
        return ResponseEntity.ok(service.analyze(trimmed));
    }

    private static ResponseEntity<Map<String, String>> error(String text) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("error", text));
    }
}
