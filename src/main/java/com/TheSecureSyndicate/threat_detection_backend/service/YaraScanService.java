package com.TheSecureSyndicate.threat_detection_backend.service;

import com.TheSecureSyndicate.threat_detection_backend.model.YaraResult;
import com.TheSecureSyndicate.threat_detection_backend.repository.YaraResultRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;

@Service
public class YaraScanService {

    private static final Logger logger = LoggerFactory.getLogger(YaraScanService.class);

    @Autowired
    private YaraResultRepository yaraResultRepository;

    @Value("${app.yara.binary-path:C:/Tools/yara-4.5.5-2368-win64/yara64.exe}")
    private String yaraBinaryPath;

    @Value("${app.yara.rules-path:./yara-rules/}")
    private String yaraRulesPath;

    public YaraScanService() {
    }

    public YaraScanService(YaraResultRepository yaraResultRepository, String yaraBinaryPath, String yaraRulesPath) {
        this.yaraResultRepository = yaraResultRepository;
        this.yaraBinaryPath = yaraBinaryPath;
        this.yaraRulesPath = yaraRulesPath;
    }

    @PostConstruct
    public void init() {
        verifyYaraPrerequisites();
    }

    public boolean verifyYaraPrerequisites() {
        File binary = new File(yaraBinaryPath);
        if (!binary.exists() || !binary.isFile()) {
            logger.warn("⚠️ YARA executable not found at: {}", binary.getAbsolutePath());
            return false;
        }

        try {
            List<File> rules = resolveRuleFiles();
            if (rules.isEmpty()) {
                logger.warn("⚠️ No YARA rule files (.yar/.yara) found at: {}", yaraRulesPath);
                return false;
            }
            logger.info("✅ YARA prerequisites verified. Binary: {}, Rule files: {}", binary.getAbsolutePath(), rules);
            return true;
        } catch (Exception e) {
            logger.warn("⚠️ YARA rules verification failed: {}", e.getMessage());
            return false;
        }
    }

    public List<File> resolveRuleFiles() {
        File path = new File(yaraRulesPath);
        if (!path.exists()) {
            throw new IllegalStateException("YARA rules path does not exist: " + path.getAbsolutePath());
        }

        List<File> ruleFiles = new ArrayList<>();
        if (path.isDirectory()) {
            File[] files = path.listFiles((dir, name) -> {
                String lower = name.toLowerCase();
                return lower.endsWith(".yar") || lower.endsWith(".yara");
            });
            if (files != null && files.length > 0) {
                Arrays.sort(files, Comparator.comparing(File::getName));
                ruleFiles.addAll(Arrays.asList(files));
            } else {
                throw new IllegalStateException("No .yar or .yara rule files found in directory: " + path.getAbsolutePath());
            }
        } else if (path.isFile()) {
            ruleFiles.add(path);
        }
        return ruleFiles;
    }

    public YaraResult scanFile(Path filePath, String binaryId) {
        File binary = new File(yaraBinaryPath);
        if (!binary.exists() || !binary.isFile()) {
            throw new IllegalStateException("YARA executable not found at: " + binary.getAbsolutePath());
        }

        List<File> ruleFiles = resolveRuleFiles();
        if (ruleFiles.isEmpty()) {
            throw new IllegalStateException("No verified YARA rule files available for scan.");
        }

        try {
            List<String> command = new ArrayList<>();
            command.add(binary.getAbsolutePath());
            command.add("-r");
            for (File rf : ruleFiles) {
                command.add(rf.getAbsolutePath());
            }
            command.add(filePath.toAbsolutePath().toString());

            ProcessBuilder pb = new ProcessBuilder(command);
            Process process = pb.start();

            List<String> matchedRules = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty()) {
                        // Extract rule name from YARA output line (e.g., "Suspicious_PE_Name file.exe")
                        String ruleName = line.split("\\s+")[0].trim();
                        matchedRules.add(ruleName);
                    }
                }
            }

            StringBuilder errorOutput = new StringBuilder();
            try (BufferedReader errReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String errLine;
                while ((errLine = errReader.readLine()) != null) {
                    errorOutput.append(errLine).append("\n");
                }
            }

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                logger.warn("YARA process returned exit code {}: {}", exitCode, errorOutput.toString().trim());
            }

            boolean matched = !matchedRules.isEmpty();
            String matchedRulesString = String.join(",", matchedRules);

            YaraResult result = new YaraResult(
                UUID.randomUUID().toString(),
                binaryId,
                matched,
                matchedRulesString,
                Instant.now()
            );

            yaraResultRepository.save(result);
            return result;

        } catch (Exception e) {
            throw new RuntimeException("YARA scan failed: " + e.getMessage(), e);
        }
    }

    public String getYaraBinaryPath() {
        return yaraBinaryPath;
    }

    public void setYaraBinaryPath(String yaraBinaryPath) {
        this.yaraBinaryPath = yaraBinaryPath;
    }

    public String getYaraRulesPath() {
        return yaraRulesPath;
    }

    public void setYaraRulesPath(String yaraRulesPath) {
        this.yaraRulesPath = yaraRulesPath;
    }
}
