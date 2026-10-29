package com.TheSecureSyndicate.threat_detection_backend.service;

import com.TheSecureSyndicate.threat_detection_backend.dto.MLRequest;
import com.TheSecureSyndicate.threat_detection_backend.dto.MLResponse;
import com.TheSecureSyndicate.threat_detection_backend.model.BinaryFile;
import com.TheSecureSyndicate.threat_detection_backend.model.YaraResult;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.List;

@Service
public class MLScoringService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final String mlUrl = "http://localhost:5000/analyze";

    public MLResponse scoreBinary(BinaryFile binary, YaraResult yaraResult) {
        MLRequest request = new MLRequest();
        request.setEntropy(binary.getEntropy());
        request.setSize(binary.getSize());

        List<String> yaraHits = Arrays.asList(yaraResult.getMatchedRules().split("\n"));
        request.setYaraHits(yaraHits);

        // Placeholder: static imports list
        request.setImports(List.of("kernel32.dll", "wininet.dll"));

        return restTemplate.postForObject(mlUrl, request, MLResponse.class);
    }
}
