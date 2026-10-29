package com.TheSecureSyndicate.threat_detection_backend.controller;

import com.TheSecureSyndicate.threat_detection_backend.dto.CIUploadRequest;
import com.TheSecureSyndicate.threat_detection_backend.dto.AnalysisSummaryResponse;
import com.TheSecureSyndicate.threat_detection_backend.model.AnalysisResult;
import com.TheSecureSyndicate.threat_detection_backend.model.BinaryFile;
import com.TheSecureSyndicate.threat_detection_backend.model.PESectionInfo;
import com.TheSecureSyndicate.threat_detection_backend.repository.AnalysisResultRepository;
import com.TheSecureSyndicate.threat_detection_backend.repository.BinaryFileRepository;
//import com.TheSecureSyndicate.threat_detection_backend.service.CuckooSandboxService;
import com.TheSecureSyndicate.threat_detection_backend.service.FileStorageService;
import com.TheSecureSyndicate.threat_detection_backend.service.StaticAnalysisService;
import com.TheSecureSyndicate.threat_detection_backend.service.YaraScanService;
import com.TheSecureSyndicate.threat_detection_backend.service.MLScoringService;
import com.TheSecureSyndicate.threat_detection_backend.model.YaraResult;
import com.TheSecureSyndicate.threat_detection_backend.dto.MLResponse;
import com.TheSecureSyndicate.threat_detection_backend.util.EntropyUtil;
import com.TheSecureSyndicate.threat_detection_backend.util.FuzzyHashUtil;
import com.TheSecureSyndicate.threat_detection_backend.util.HashUtil;
import com.TheSecureSyndicate.threat_detection_backend.util.PEFunctionParser;
import com.TheSecureSyndicate.threat_detection_backend.util.PEFunctionParser.PEFunctionResult;
import com.TheSecureSyndicate.threat_detection_backend.util.PEFunctionParser.PEHeaderResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class FileIngestionController {

    private static final Logger logger = LoggerFactory.getLogger(FileIngestionController.class);
    private static final long MAX_ALLOWED_SIZE = 100 * 1024 * 1024L; // 100 MB
    private static final Set<String> ALLOWED_TYPES = Set.of(
            "application/x-dosexec",
            "application/octet-stream",
            "application/x-msdownload"
    );

    private final FileStorageService fileStorageService;
    private final BinaryFileRepository binaryFileRepository;
    private final AnalysisResultRepository analysisResultRepository;
    private final StaticAnalysisService staticAnalysisService;
    private final YaraScanService yaraScanService;
    private final MLScoringService mlScoringService;

    public FileIngestionController(
            FileStorageService fileStorageService,
            BinaryFileRepository binaryFileRepository,
            AnalysisResultRepository analysisResultRepository,
            StaticAnalysisService staticAnalysisService,
            YaraScanService yaraScanService,
            MLScoringService mlScoringService
    ) {
        this.fileStorageService = fileStorageService;
        this.binaryFileRepository = binaryFileRepository;
        this.analysisResultRepository = analysisResultRepository;
        this.staticAnalysisService = staticAnalysisService;
        this.yaraScanService = yaraScanService;
        this.mlScoringService = mlScoringService;
    }

    @PostMapping("/upload")
    public ResponseEntity<AnalysisSummaryResponse> uploadFile(@RequestParam MultipartFile file) throws Exception {
        if (file.getSize() > MAX_ALLOWED_SIZE) {
            return ResponseEntity.badRequest().body(null);
        }

        String id = UUID.randomUUID().toString();
        Path savedPath = fileStorageService.saveTemp(file, id);
        String mimeType = Files.probeContentType(savedPath);
        if (mimeType == null) {
            mimeType = "application/octet-stream";
        }

        if (!ALLOWED_TYPES.contains(mimeType)) {
            Files.deleteIfExists(savedPath);
            return ResponseEntity.badRequest().body(null);
        }

        byte[] fileBytes = Files.readAllBytes(savedPath);

        BinaryFile binary = new BinaryFile(
                id,
                file.getOriginalFilename(),
                savedPath.toString(),
                file.getSize(),
                EntropyUtil.calculateEntropy(fileBytes),
                HashUtil.calculateSHA256(savedPath),
                Instant.now()
        );
        binary.setSsdeepHash(FuzzyHashUtil.calculateSSDEEP(savedPath));
        binaryFileRepository.save(binary);

        // 🔍 Static analysis
        AnalysisResult result = staticAnalysisService.analyze(binary);

        // 🔍 PE function parsing
        try {
            PEFunctionResult functions = PEFunctionParser.parseFunctionsFromUpload(file);
            if (functions != null) {
                result.setImportedFunctions(functions.getImportedFunctions());
                result.setExportedFunctions(functions.getExportedFunctions());
                logger.info("Imported Functions count: {}", functions.getImportedFunctions().size());
            }
        } catch (Exception e) {
            logger.warn("Failed to parse PE functions: {}", e.getMessage());
        }

        // 🔍 YARA pattern scan
        YaraResult yaraResult = null;
        try {
            yaraResult = yaraScanService.scanFile(savedPath, binary.getId());
            if (yaraResult != null) {
                result.setYaraMatched(yaraResult.isMatched());
                result.setMatchedRules(parseMatchedRules(yaraResult.getMatchedRules()));
                logger.info("YARA Scan: matched={}, rules={}", yaraResult.isMatched(), yaraResult.getMatchedRules());
            }
        } catch (Exception e) {
            logger.warn("YARA scan encountered an issue: {}", e.getMessage());
        }

        // 🔍 ML / Heuristic risk scoring
        try {
            MLResponse mlResponse = mlScoringService.scoreBinary(binary, yaraResult);
            if (mlResponse != null) {
                result.setMlRiskScore(mlResponse.getRiskScore());
                logger.info("ML Risk Score: {}, Heuristic verdict: {}", mlResponse.getRiskScore(), mlResponse.getClassification());
            }
        } catch (Exception e) {
            logger.warn("ML scoring encountered an issue: {}", e.getMessage());
        }

        // 🔍 Calibrated Threat Classification
        String classification = "clean";
        if (result.isYaraMatched()) {
            classification = "malicious";
        } else if (result.getMlRiskScore() > 0.70) {
            classification = "malicious";
        } else if (result.getMlRiskScore() > 0.40) {
            classification = "suspicious";
        } else {
            classification = "clean";
        }
        result.setClassification(classification);

        analysisResultRepository.save(result);
        Files.deleteIfExists(savedPath);

        // choose filename in order of trust: header -> binary -> "unknown"
        String responseFilename = "unknown";
        if (result.getHeaderResult() != null && result.getHeaderResult().getFilename() != null && !result.getHeaderResult().getFilename().isBlank()) {
            responseFilename = result.getHeaderResult().getFilename();
        } else if (binary.getOriginalFilename() != null && !binary.getOriginalFilename().isBlank()) {
            responseFilename = binary.getOriginalFilename();
        }

        AnalysisSummaryResponse response = new AnalysisSummaryResponse(
                result.getBinaryId(),
                responseFilename,
                result.isYaraMatched(),
                result.getMatchedRules(),
                result.getMlRiskScore(),
                result.getClassification(),
                result.getMachineType(),
                result.getEntryPoint(),
                result.getImageBase(),
                result.getSubsystem(),
                result.getSections(),
                result.getPacked()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/ci-upload")
    public ResponseEntity<AnalysisSummaryResponse> uploadFromCI(@RequestBody CIUploadRequest request) throws Exception {
        byte[] fileBytes = Base64.getDecoder().decode(request.getBase64File());
        if (fileBytes.length > MAX_ALLOWED_SIZE) {
            return ResponseEntity.badRequest().body(null);
        }

        String id = UUID.randomUUID().toString();
        Path savedPath = fileStorageService.saveTemp(fileBytes, request.getFileName(), id);
        String mimeType = Files.probeContentType(savedPath);
        if (mimeType == null) mimeType = "application/octet-stream";
        if (!ALLOWED_TYPES.contains(mimeType)) {
            Files.deleteIfExists(savedPath);
            return ResponseEntity.badRequest().body(null);
        }

        BinaryFile binary = new BinaryFile(
                id,
                request.getFileName(),
                savedPath.toString(),
                fileBytes.length,
                EntropyUtil.calculateEntropy(fileBytes),
                HashUtil.calculateSHA256(savedPath),
                Instant.now()
        );
        binary.setSsdeepHash(FuzzyHashUtil.calculateSSDEEP(savedPath));
        binaryFileRepository.save(binary);

        AnalysisResult result = staticAnalysisService.analyze(binary);

        // 🔍 PE function parsing
        try {
            MultipartFile wrapped = new CIUploadRequest.MultipartWrapper(request.getFileName(), fileBytes);
            PEFunctionResult functions = PEFunctionParser.parseFunctionsFromUpload(wrapped);
            if (functions != null) {
                result.setImportedFunctions(functions.getImportedFunctions());
                result.setExportedFunctions(functions.getExportedFunctions());
            }
        } catch (Exception e) {
            logger.warn("Failed to parse PE functions: {}", e.getMessage());
        }

        // 🔍 YARA pattern scan
        YaraResult yaraResult = null;
        try {
            yaraResult = yaraScanService.scanFile(savedPath, binary.getId());
            if (yaraResult != null) {
                result.setYaraMatched(yaraResult.isMatched());
                result.setMatchedRules(parseMatchedRules(yaraResult.getMatchedRules()));
            }
        } catch (Exception e) {
            logger.warn("YARA scan encountered an issue: {}", e.getMessage());
        }

        // 🔍 ML / Heuristic risk scoring
        try {
            MLResponse mlResponse = mlScoringService.scoreBinary(binary, yaraResult);
            if (mlResponse != null) {
                result.setMlRiskScore(mlResponse.getRiskScore());
            }
        } catch (Exception e) {
            logger.warn("ML scoring encountered an issue: {}", e.getMessage());
        }

        // 🔍 Calibrated Threat Classification
        String classification = "clean";
        if (result.isYaraMatched()) {
            classification = "malicious";
        } else if (result.getMlRiskScore() > 0.70) {
            classification = "malicious";
        } else if (result.getMlRiskScore() > 0.40) {
            classification = "suspicious";
        } else {
            classification = "clean";
        }
        result.setClassification(classification);

        analysisResultRepository.save(result);
        Files.deleteIfExists(savedPath);

        // choose filename in order of trust: header -> binary -> "unknown"
        String responseFilename = "unknown";
        if (result.getHeaderResult() != null && result.getHeaderResult().getFilename() != null && !result.getHeaderResult().getFilename().isBlank()) {
            responseFilename = result.getHeaderResult().getFilename();
        } else if (binary.getOriginalFilename() != null && !binary.getOriginalFilename().isBlank()) {
            responseFilename = binary.getOriginalFilename();
        }

        AnalysisSummaryResponse response = new AnalysisSummaryResponse(
                result.getBinaryId(),
                responseFilename,
                result.isYaraMatched(),
                result.getMatchedRules(),
                result.getMlRiskScore(),
                result.getClassification(),
                result.getMachineType(),
                result.getEntryPoint(),
                result.getImageBase(),
                result.getSubsystem(),
                result.getSections(),
                result.getPacked()
        );

        return ResponseEntity.ok(response);
    }

    private List<String> parseMatchedRules(String matchedRulesStr) {
        List<String> list = new ArrayList<>();
        if (matchedRulesStr != null && !matchedRulesStr.isBlank()) {
            String[] tokens = matchedRulesStr.split("[\\r\\n,]+");
            for (String t : tokens) {
                String trimmed = t.trim();
                if (!trimmed.isEmpty()) {
                    list.add(trimmed);
                }
            }
        }
        return list;
    }
}
