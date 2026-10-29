package com.TheSecureSyndicate.threat_detection_backend.service;

import com.TheSecureSyndicate.threat_detection_backend.dto.MLRequest;
import com.TheSecureSyndicate.threat_detection_backend.dto.MLResponse;
import com.TheSecureSyndicate.threat_detection_backend.model.BinaryFile;
import com.TheSecureSyndicate.threat_detection_backend.model.YaraResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class MLScoringService {

    private static final Logger logger = LoggerFactory.getLogger(MLScoringService.class);
    private final RestTemplate restTemplate = new RestTemplate();
    private final String mlUrl = "http://localhost:5000/analyze";

    public MLResponse scoreBinary(BinaryFile binary, YaraResult yaraResult) {
        MLRequest request = new MLRequest();
        request.setEntropy(binary.getEntropy());
        request.setSize(binary.getSize());
        request.setHash(binary.getHash());
        request.setCuckooScore(binary.getCuckooScore());
        request.setFileName(binary.getFileName());

        // Parse YARA matches safely
        List<String> yaraHits = new ArrayList<>();
        if (yaraResult != null && yaraResult.getMatchedRules() != null) {
            yaraHits = Arrays.stream(yaraResult.getMatchedRules().split("\r?\n"))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());
        }
        request.setYaraHits(yaraHits);
        request.setYaraHitCount(yaraHits.size());

        // Try to infer imports from YARA rule names when possible (best-effort)
        List<String> imports = yaraHits.stream()
                .flatMap(r -> Arrays.stream(r.split("[^A-Za-z0-9_.]")))
                .map(String::toLowerCase)
                .filter(tok -> tok.endsWith(".dll") || tok.endsWith(".exe"))
                .distinct()
                .collect(Collectors.toList());

        // Fallback: if none inferred, leave imports empty (avoid static placeholder)
        request.setImports(imports);

        logger.debug("ML request built: entropy={}, size={}, yaraHits={}, imports={}, cuckooScore={}",
                request.getEntropy(), request.getSize(), request.getYaraHits(), request.getImports(), request.getCuckooScore());

        try {
            MLResponse response = restTemplate.postForObject(mlUrl, request, MLResponse.class);
            if (response == null) {
                logger.warn("ML service returned null response, using fallback heuristic");
                return createFallbackResponse(binary, yaraHits.size());
            }
            logger.debug("ML response: {}", response);
            return response;
        } catch (RestClientException e) {
            logger.warn("Error calling ML service: {} - using fallback heuristic", e.getMessage());
            return createFallbackResponse(binary, yaraHits.size());
        }
    }

    private MLResponse createFallbackResponse(BinaryFile binary, int yaraCount) {
        MLResponse fallback = new MLResponse();
        double score;
        if (yaraCount > 0) {
            score = Math.min(1.0, 0.55 + (yaraCount * 0.25));
        } else {
            double entropy = binary != null ? binary.getEntropy() : 0.0;
            long size = binary != null ? binary.getSize() : 0L;

            if (entropy > 7.92 && size > 0 && size < 500 * 1024L) {
                // Highly concentrated entropy in small file (potential dropper/shellcode)
                score = 0.45;
            } else if (entropy > 7.7) {
                // High compression (standard for installers/packed binaries)
                score = 0.20;
            } else if (entropy > 6.0) {
                score = 0.10;
            } else {
                score = 0.05;
            }
        }
        score = Math.round(score * 1000.0) / 1000.0;
        fallback.setRiskScore(score);
        fallback.setClassification(score > 0.70 ? "malicious" : (score > 0.40 ? "suspicious" : "clean"));
        return fallback;
    }
}
