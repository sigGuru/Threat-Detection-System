package com.TheSecureSyndicate.threat_detection_backend.service;

import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.coffheader.COFFFileHeader;
import io.github.struppigel.parser.optheader.OptionalHeader;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionTable;
import io.github.struppigel.parser.sections.edata.ExportEntry;
import io.github.struppigel.parser.sections.idata.ImportDLL;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.TheSecureSyndicate.threat_detection_backend.model.PESectionInfo;
import com.TheSecureSyndicate.threat_detection_backend.model.BinaryFile;
import com.TheSecureSyndicate.threat_detection_backend.model.AnalysisResult;
import com.TheSecureSyndicate.threat_detection_backend.util.PEFunctionParser;
import com.TheSecureSyndicate.threat_detection_backend.util.PEFunctionParser.PEHeaderResult;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class StaticAnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(StaticAnalysisService.class);
    private static final int CHARACTERISTICS_DB_MAX = 4000;

    // ========================================================
    // IMPORT / EXPORT PARSING
    // ========================================================
    public static List<String> extractImportedFunctions(File peFile) throws Exception {
        Objects.requireNonNull(peFile, "peFile cannot be null");
        List<String> results = new ArrayList<>();
        PEData data = PELoader.loadPE(peFile);
        if (data == null) return results;

        List<ImportDLL> dlls = data.loadImports();
        if (dlls == null) return results;

        for (ImportDLL dll : dlls) {
            if (dll == null) continue;
            String dllName = safeInvokeString(dll, "getName", "name");
            if (dllName == null) dllName = "UNKNOWN_DLL";

            Object allImports = safeInvokeObject(dll, "getAllImports", "allImports", "getImports");
            if (allImports instanceof List) {
                for (Object imp : (List<?>) allImports) {
                    String fname = extractNameFromImportObject(imp);
                    if (fname != null && !fname.isEmpty())
                        results.add(dllName + "::" + fname);
                    else {
                        String ord = extractOrdinalFromImportObject(imp);
                        if (ord != null && !ord.isEmpty())
                            results.add(dllName + "::Ordinal_" + ord);
                        else {
                            String fallback = safeToString(imp);
                            if (fallback != null && !fallback.isEmpty())
                                results.add(dllName + "::" + fallback);
                        }
                    }
                }
            }
        }
        return results;
    }

    public static List<String> extractExportedFunctions(File peFile) throws Exception {
        Objects.requireNonNull(peFile, "peFile cannot be null");
        List<String> results = new ArrayList<>();
        PEData data = PELoader.loadPE(peFile);
        if (data == null) return results;

        List<ExportEntry> entries = data.loadExports();
        if (entries == null) return results;

        for (ExportEntry e : entries) {
            if (e == null) continue;
            // use shared helper from PEFunctionParser (must be declared public static there)
            String name = PEFunctionParser.tryInvokeAsString(e, "getName", "name", "toString");
            if (name != null && !name.isEmpty()) {
                results.add(name);
            } else {
                String ord = PEFunctionParser.tryInvokeAsString(e, "ordinal", "getOrdinal");
                if (ord != null && !ord.isEmpty()) {
                    results.add("Ordinal_" + ord);
                } else {
                    String fallback = safeToString(e);
                    if (fallback != null && !fallback.isEmpty()) {
                        results.add(fallback);
                    }
                }
            }
        }
        return results;
    }

    // ========================================================
    // HEADER & SECTION PARSING
    // ========================================================
    public static PEHeaderResult extractHeaderAndSections(File peFile) throws Exception {
        return PEFunctionParser.extractHeaderAndSections(peFile);
    }

    // ========================================================
    // MAIN ANALYSIS ENTRYPOINT
    // ========================================================
    public AnalysisResult analyze(BinaryFile binary) {
        AnalysisResult result = new AnalysisResult();
        try {
            File peFile = new File(binary.getFilePath());
            PEHeaderResult header = extractHeaderAndSections(peFile);

            result.setBinaryId(binary.getId());
            result.setFilename(binary.getOriginalFilename());
            result.setClassification("clean");
            result.setPacked(header != null && PEFunctionParser.isPacked(header));
            result.setHeaderResult(header);

            logger.info("🧩 Static Analysis: {} -> Machine: {}, EP: 0x{}, Packed: {}",
                    binary.getOriginalFilename(),
                    header != null ? header.getMachineType() : "unknown",
                    Long.toHexString(header != null ? header.getEntryPoint() : 0L),
                    result.isPacked());

        } catch (Exception e) {
            logger.error("❌ Error analyzing binary {}: {}", binary.getOriginalFilename(), e.getMessage(), e);
            result.setClassification("error");
        }
        return result;
    }

    // ========================================================
    // HELPER METHODS
    // ========================================================
    private static String truncateCharacteristics(String s) {
        if (s == null) return null;
        if (s.length() <= CHARACTERISTICS_DB_MAX) return s;
        String[] tokens = s.split(",\\s*");
        StringBuilder sb = new StringBuilder();
        for (String token : tokens) {
            if (sb.length() + token.length() + 2 > CHARACTERISTICS_DB_MAX) {
                sb.append(" ...");
                break;
            }
            if (sb.length() > 0) sb.append(", ");
            sb.append(token);
        }
        return sb.toString();
    }

    private static String safeInvokeString(Object target, String... candidates) {
        Object val = safeInvokeObject(target, candidates);
        return val == null ? null : val.toString();
    }

    private static Object safeInvokeObject(Object target, String... candidates) {
        if (target == null) return null;
        for (String m : candidates) {
            try {
                Method mm = target.getClass().getMethod(m);
                return mm.invoke(target);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ignored) {}
        }
        return null;
    }

    private static String getString(Object obj, String... methods) {
        if (obj == null) return null;
        for (String m : methods) {
            try {
                Method mm = obj.getClass().getMethod(m);
                Object v = mm.invoke(obj);
                if (v != null) return v.toString();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static Long getLong(Object obj, String... methods) {
        if (obj == null) return null;
        for (String m : methods) {
            try {
                Method mm = obj.getClass().getMethod(m);
                Object v = mm.invoke(obj);
                if (v instanceof Number) return ((Number) v).longValue();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static Double getDouble(Object obj, String... methods) {
        if (obj == null) return null;
        for (String m : methods) {
            try {
                Method mm = obj.getClass().getMethod(m);
                Object v = mm.invoke(obj);
                if (v instanceof Number) return ((Number) v).doubleValue();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static Long getOptionalHeaderLong(Object optional, String... methods) {
        return getLong(optional, methods);
    }

    private static String getOptionalHeaderString(Object optional, String... methods) {
        return getString(optional, methods);
    }

    private static String safeToString(Object o) {
        if (o == null) return null;
        try {
            return o.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    private static String extractNameFromImportObject(Object imp) {
        if (imp == null) return null;
        for (String m : new String[]{"getName", "name", "getImportName", "importName", "toString"}) {
            try {
                Method mm = imp.getClass().getMethod(m);
                Object ret = mm.invoke(imp);
                if (ret != null) return String.valueOf(ret);
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static String extractOrdinalFromImportObject(Object imp) {
        if (imp == null) return null;
        for (String m : new String[]{"ordinal", "getOrdinal", "getOrdinalNumber"}) {
            try {
                Method mm = imp.getClass().getMethod(m);
                Object ret = mm.invoke(imp);
                if (ret != null) return String.valueOf(ret);
            } catch (Exception ignored) {}
        }
        return null;
    }

    // ========================================================
    // DTO CLASSES - none here: use PEFunctionParser.PEHeaderResult
    // ========================================================
}
