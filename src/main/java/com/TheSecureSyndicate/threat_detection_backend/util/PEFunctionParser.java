package com.TheSecureSyndicate.threat_detection_backend.util;

import io.github.struppigel.parser.PELoader;
import io.github.struppigel.parser.PEData;
import io.github.struppigel.parser.coffheader.COFFFileHeader;
import io.github.struppigel.parser.optheader.OptionalHeader;
import io.github.struppigel.parser.optheader.StandardFieldEntryKey;
import io.github.struppigel.parser.optheader.WindowsEntryKey;
import io.github.struppigel.parser.sections.SectionHeader;
import io.github.struppigel.parser.sections.SectionHeaderKey;
import io.github.struppigel.parser.sections.SectionTable;
import io.github.struppigel.parser.sections.edata.ExportEntry;
import io.github.struppigel.parser.sections.idata.ImportDLL;

import org.springframework.web.multipart.MultipartFile;
import com.TheSecureSyndicate.threat_detection_backend.model.PESectionInfo;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PEFunctionParser {

    private static final Logger logger = LoggerFactory.getLogger(PEFunctionParser.class);
    private static final int CHARACTERISTICS_DB_MAX = 250; // keep below 255 DB column limit

    // -------------------------
    // Imports / Exports parsing
    // -------------------------

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
                    if (fname != null && !fname.isEmpty()) results.add(dllName + "::" + fname);
                    else {
                        String ord = extractOrdinalFromImportObject(imp);
                        if (ord != null && !ord.isEmpty()) results.add(dllName + "::Ordinal_" + ord);
                        else {
                            String fallback = safeToString(imp);
                            if (fallback != null && !fallback.isEmpty()) results.add(dllName + "::" + fallback);
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

            String name = tryInvokeAsString(e, "getName", "name", "toString");
            if (name != null && !name.isEmpty()) results.add(name);
            else {
                String ord = tryInvokeAsString(e, "ordinal", "getOrdinal");
                if (ord != null && !ord.isEmpty()) results.add("Ordinal_" + ord);
                else {
                    String fallback = safeToString(e);
                    if (fallback != null && !fallback.isEmpty()) results.add(fallback);
                }
            }
        }

        return results;
    }

    // -------------------------
    // Headers & Sections parsing
    // -------------------------

    /**
     * Try to invoke methods that return numeric types.
     * If none found, also try to parse numbers from string-returning methods like getInfo() or toString().
     */
    private static Long getOptionalHeaderLong(Object optional, String... methods) {
        if (optional == null) return null;
        // try numeric-returning methods first
        for (String method : methods) {
            try {
                Method m = optional.getClass().getMethod(method);
                Object value = m.invoke(optional);
                if (value instanceof Number) return ((Number) value).longValue();
                // if string-ish, try to parse numeric out of it
                if (value != null) {
                    Long parsed = parseLongFromObject(value);
                    if (parsed != null) return parsed;
                }
            } catch (NoSuchMethodException ns) {
                // ignore - try next
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }

        // fallback: try well-known descriptive methods that contain the data as text
        String[] infoCandidates = {"getStandardFieldsInfo", "getInfo", "getWindowsSpecificInfo", "getStandardFields", "toString", "getDataDirInfo"};
        for (String c : infoCandidates) {
            try {
                Method m = optional.getClass().getMethod(c);
                Object val = m.invoke(optional);
                if (val != null) {
                    Long parsed = parseLongFromObject(val);
                    if (parsed != null) return parsed;
                }
            } catch (NoSuchMethodException ns) {
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }

        return null;
    }

    private static String getOptionalHeaderString(Object optional, String... methods) {
        if (optional == null) return null;
        for (String method : methods) {
            try {
                Method m = optional.getClass().getMethod(method);
                Object value = m.invoke(optional);
                if (value != null) return value.toString();
            } catch (NoSuchMethodException ns) {
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }
        // fallback to getInfo/toString
        try {
            Method m = optional.getClass().getMethod("getInfo");
            Object v = m.invoke(optional);
            if (v != null) return v.toString();
        } catch (Exception ignored) {}
        try {
            Method m = optional.getClass().getMethod("toString");
            Object v = m.invoke(optional);
            if (v != null) return v.toString();
        } catch (Exception ignored) {}
        return null;
    }

    private static Double getOptionalHeaderDouble(Object optional, String... methods) {
        if (optional == null) return null;
        for (String method : methods) {
            try {
                Method m = optional.getClass().getMethod(method);
                Object value = m.invoke(optional);
                if (value instanceof Number) return ((Number) value).doubleValue();
                if (value != null) {
                    Double parsed = parseDoubleFromObject(value);
                    if (parsed != null) return parsed;
                }
            } catch (NoSuchMethodException ns) {
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }
        return null;
    }

    private static Long getLong(Object obj, String... methods) {
        if (obj == null) return null;
        // numeric-returning methods first
        for (String method : methods) {
            try {
                Method m = obj.getClass().getMethod(method);
                Object value = m.invoke(obj);
                if (value instanceof Number) return ((Number) value).longValue();
                if (value != null) {
                    Long parsed = parseLongFromObject(value);
                    if (parsed != null) return parsed;
                }
            } catch (NoSuchMethodException ns) {
                // ignore
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }

        // fallback: probe descriptive methods that may include the number
        String[] fallbackCandidates = {"getInfo", "getEntryMap", "toString", "get"};
        for (String c : fallbackCandidates) {
            try {
                Method m = obj.getClass().getMethod(c);
                Object v = m.invoke(obj);
                if (v != null) {
                    Long parsed = parseLongFromObject(v);
                    if (parsed != null) return parsed;
                }
            } catch (NoSuchMethodException ns) {
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }

        return null;
    }

    private static Double getDouble(Object obj, String... methods) {
        if (obj == null) return null;
        for (String method : methods) {
            try {
                Method m = obj.getClass().getMethod(method);
                Object value = m.invoke(obj);
                if (value instanceof Number) return ((Number) value).doubleValue();
                if (value != null) {
                    Double parsed = parseDoubleFromObject(value);
                    if (parsed != null) return parsed;
                }
            } catch (NoSuchMethodException ns) {
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }
        // fallback to parsing descriptive outputs
        String[] fallbackCandidates = {"getInfo", "toString", "getEntryMap", "get"};
        for (String c : fallbackCandidates) {
            try {
                Method m = obj.getClass().getMethod(c);
                Object v = m.invoke(obj);
                if (v != null) {
                    Double parsed = parseDoubleFromObject(v);
                    if (parsed != null) return parsed;
                }
            } catch (NoSuchMethodException ns) {
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }
        return null;
    }

    private static String getString(Object obj, String... methods) {
        if (obj == null) return null;
        for (String method : methods) {
            try {
                Method m = obj.getClass().getMethod(method);
                Object value = m.invoke(obj);
                if (value != null) return value.toString();
            } catch (NoSuchMethodException ns) {
            } catch (InvocationTargetException | IllegalAccessException ignored) {}
        }
        // fallback
        try {
            Method m = obj.getClass().getMethod("toString");
            Object v = m.invoke(obj);
            if (v != null) return v.toString();
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * Truncate to safe length for DB columns.
     */
    private static String truncateCharacteristics(String s) {
        if (s == null) return null;
        if (s.length() <= CHARACTERISTICS_DB_MAX) return s;
        return s.substring(0, CHARACTERISTICS_DB_MAX);
    }

    /**
     * Parse long from various object types:
     * - If Number -> direct
     * - If Map -> look for keys with VIRTUAL_SIZE, SIZE_OF_RAW_DATA, VIRTUAL_ADDRESS etc.
     * - If String -> regex search for decimal or hex numbers near likely labels.
     */
    private static Long parseLongFromObject(Object value) {
        if (value == null) return null;
        if (value instanceof Number) return ((Number) value).longValue();

        // Map-like (entry map) -> try keys
        if (value instanceof Map) {
            Map<?,?> m = (Map<?,?>) value;
            // try common keys
            String[] possibleKeys = {"VIRTUAL_SIZE","virtual size","SIZE_OF_RAW_DATA","size of raw data","VIRTUAL_ADDRESS","virtual address","ADDR_OF_ENTRY_POINT","ADDRESS_OF_ENTRY_POINT","ADDR_OF_ENTRY"};
            for (String k : possibleKeys) {
                for (Object key : m.keySet()) {
                    String ks = key.toString().toUpperCase();
                    if (ks.contains(k.replace(" ", "").toUpperCase()) || ks.contains(k.toUpperCase())) {
                        Object vv = m.get(key);
                        Long parsed = parseLongFromObject(vv);
                        if (parsed != null) return parsed;
                    }
                }
            }
            // value iteration fallback
            for (Object v : m.values()) {
                Long parsed = parseLongFromObject(v);
                if (parsed != null) return parsed;
            }
        }

        // Text parsing: look for patterns like:
        // "virtual size: 244135 (0x3b9a7)" or "address of entry point: 5360 (0x14f0)" or "image base: 4194304 (0x400000)"
        String s = value.toString();
        if (s == null || s.isEmpty()) return null;

        // label-based regex attempts (order matters)
        String[][] labelPatterns = {
                {"address of entry point", null},
                {"ADDR_OF_ENTRY_POINT", null},
                {"entry point", null},
                {"image base", null},
                {"imagebase", null},
                {"image base:", null},
                {"virtual size", null},
                {"VIRTUAL_SIZE", null},
                {"size of raw data", null},
                {"SIZE_OF_RAW_DATA", null},
                {"virtual address", null},
                {"VIRTUAL_ADDRESS", null},
                {"address of base of code", null}
        };

        // try label-based extraction
        for (String[] lp : labelPatterns) {
            String label = lp[0];
            Pattern p1 = Pattern.compile("(?i)" + Pattern.quote(label) + "\\s*[:]?\\s*(\\d+)");
            Matcher m1 = p1.matcher(s);
            if (m1.find()) {
                try { return Long.parseLong(m1.group(1)); } catch (NumberFormatException ignored) {}
            }
            // look for hex after parentheses: e.g. (0x14f0)
            Pattern p2 = Pattern.compile("(?i)" + Pattern.quote(label) + "[^\\n\\r]*\\(0x([0-9a-fA-F]+)\\)");
            Matcher m2 = p2.matcher(s);
            if (m2.find()) {
                try { return Long.parseLong(m2.group(1), 16); } catch (NumberFormatException ignored) {}
            }
        }

        // general decimal number first occurrence
        Pattern dec = Pattern.compile("\\b(\\d{2,})\\b"); // at least 2 digits to avoid small noise
        Matcher md = dec.matcher(s);
        if (md.find()) {
            try { return Long.parseLong(md.group(1)); } catch (NumberFormatException ignored) {}
        }

        // general hex 0x... anywhere
        Pattern hx = Pattern.compile("0x([0-9a-fA-F]+)");
        Matcher mh = hx.matcher(s);
        if (mh.find()) {
            try { return Long.parseLong(mh.group(1), 16); } catch (NumberFormatException ignored) {}
        }

        return null;
    }

    private static Double parseDoubleFromObject(Object value) {
        if (value == null) return null;
        if (value instanceof Number) return ((Number) value).doubleValue();
        String s = value.toString();
        if (s == null || s.isEmpty()) return null;
        // decimal with optional fraction
        Pattern p = Pattern.compile("([0-9]+\\.[0-9]+|[0-9]+)");
        Matcher m = p.matcher(s);
        if (m.find()) {
            try { return Double.parseDouble(m.group(1)); } catch (NumberFormatException ignored) {}
        }
        return null;
    }

    public static PEHeaderResult extractHeaderAndSections(File peFile) throws Exception {
        Objects.requireNonNull(peFile, "peFile cannot be null");

        PEData data = PELoader.loadPE(peFile);
        if (data == null) return null;

        COFFFileHeader coff = data.getCOFFFileHeader();
        OptionalHeader optional = data.getOptionalHeader();
        SectionTable secTable = data.getSectionTable();

        // -----------------------
        // Create the result object early and set filename
        // -----------------------
        PEHeaderResult result = new PEHeaderResult();

        // 🧩 FIX: Set the filename immediately
        if (peFile != null && peFile.getName() != null) {
            result.setFilename(peFile.getName());
        } else {
            result.setFilename("unknown");
        }

        // -----------------------
        // DEBUGGING: List Section methods and values
        // -----------------------
        if (secTable != null && secTable.getSectionHeaders() != null) {
            for (SectionHeader section : secTable.getSectionHeaders()) {
                System.out.println("---- Section: " + section.getName() + " ----");
                for (Method m : section.getClass().getMethods()) {
                    if (m.getParameterCount() == 0) {
                        try {
                            Object val = m.invoke(section);
                            if (val != null) System.out.println(m.getName() + " -> " + val);
                        } catch (Exception ignored) {}
                    }
                }
            }
        }

        // -----------------------
        // DEBUGGING: List OptionalHeader methods and values
        // -----------------------
        if (optional != null) {
            System.out.println("---- Optional Header Methods ----");
            for (Method m : optional.getClass().getMethods()) {
                if (m.getParameterCount() == 0) {
                    try {
                        Object val = m.invoke(optional);
                        if (val != null) System.out.println(m.getName() + " -> " + val);
                    } catch (Exception ignored) {}
                }
            }
        }

        // -----------------------
        // Extraction Logic
        // -----------------------

        // COFF header
        if (coff != null) {
            result.setMachineType(coff.getMachineType() != null ? coff.getMachineType().name() : "UNKNOWN");
            Date dt = coff.getTimeDate();
            result.setTimestamp(dt != null ? dt.getTime() : 0L);
            result.setNumSections(coff.getNumberOfSections());
            result.setCharacteristics(coff.getCharacteristics() != null ? coff.getCharacteristics().toString() : "");
        }

        // Optional header
        if (optional != null) {
            long entryPoint = 0L;
            try {
                entryPoint = optional.get(StandardFieldEntryKey.ADDR_OF_ENTRY_POINT);
            } catch (Exception e) {
                Long ep = getOptionalHeaderLong(optional, "getAddressOfEntryPoint", "getEntryPoint");
                if (ep != null) entryPoint = ep;
            }
            result.setEntryPoint(entryPoint);

            long imageBase = 0L;
            try {
                imageBase = optional.get(WindowsEntryKey.IMAGE_BASE);
            } catch (Exception e) {
                Long ib = getOptionalHeaderLong(optional, "getImageBase", "getBaseOfImage");
                if (ib != null) imageBase = ib;
            }
            result.setImageBase(imageBase);

            try {
                result.setSubsystem(optional.getSubsystem() != null ? optional.getSubsystem().name() : "UNKNOWN");
            } catch (Exception e) {
                String sub = getOptionalHeaderString(optional, "getSubsystem", "subsystem");
                result.setSubsystem(sub != null ? sub : "UNKNOWN");
            }

            try {
                result.setDllCharacteristics(optional.getDllCharacteristics() != null ? optional.getDllCharacteristics().toString() : "");
            } catch (Exception e) {
                String dc = getOptionalHeaderString(optional, "getDllCharacteristics", "dllCharacteristics");
                result.setDllCharacteristics(dc != null ? dc : "");
            }

            logger.debug("PE Optional Header: entryPoint=0x{}, imageBase=0x{}, subsystem={}",
                    Long.toHexString(result.getEntryPoint()), Long.toHexString(result.getImageBase()), result.getSubsystem());
        } else {
            logger.warn("OptionalHeader is null for file: {}", peFile.getName());
        }

        // Sections
        if (secTable != null && secTable.getSectionHeaders() != null) {
            for (SectionHeader section : secTable.getSectionHeaders()) {
                if (section == null) continue;
                PESectionInfo info = new PESectionInfo();

                String name = section.getName() != null ? section.getName() : "UNKNOWN";
                long virtualSize = 0L;
                long rawSize = 0L;
                long rva = 0L;
                long pointerToRaw = 0L;

                try {
                    virtualSize = section.get(SectionHeaderKey.VIRTUAL_SIZE);
                } catch (Exception e) {
                    Long vs = getLong(section, "getVirtualSize", "getAlignedVirtualSize");
                    if (vs != null) virtualSize = vs;
                }

                try {
                    rawSize = section.get(SectionHeaderKey.SIZE_OF_RAW_DATA);
                } catch (Exception e) {
                    Long rs = getLong(section, "getSizeOfRawData", "getAlignedSizeOfRaw");
                    if (rs != null) rawSize = rs;
                }

                try {
                    rva = section.get(SectionHeaderKey.VIRTUAL_ADDRESS);
                } catch (Exception e) {
                    Long va = getLong(section, "getVirtualAddress", "getAlignedVirtualAddress");
                    if (va != null) rva = va;
                }

                try {
                    pointerToRaw = section.get(SectionHeaderKey.POINTER_TO_RAW_DATA);
                } catch (Exception ignored) {}

                String characteristics = section.getCharacteristics() != null ? section.getCharacteristics().toString() : "";
                characteristics = truncateCharacteristics(characteristics);

                // Compute exact Shannon entropy (0.0 to 8.0) directly from section raw data
                double entropy = 0.0;
                if (rawSize > 0 && pointerToRaw >= 0 && (pointerToRaw + rawSize <= peFile.length() + 4096)) {
                    try (RandomAccessFile raf = new RandomAccessFile(peFile, "r")) {
                        raf.seek(pointerToRaw);
                        int readLen = (int) Math.min(rawSize, Math.min(peFile.length() - pointerToRaw, 10 * 1024 * 1024L));
                        if (readLen > 0) {
                            byte[] sectionBytes = new byte[readLen];
                            raf.readFully(sectionBytes);
                            entropy = EntropyUtil.calculateEntropy(sectionBytes);
                        }
                    } catch (Exception e) {
                        logger.debug("Could not compute raw entropy for section {}: {}", name, e.getMessage());
                    }
                }

                // Ensure clean clamping (0.000 to 8.000)
                entropy = Math.max(0.0, Math.min(8.0, entropy));
                entropy = Math.round(entropy * 1000.0) / 1000.0;

                info.setName(name);
                info.setVirtualSize(virtualSize);
                info.setRawSize(rawSize);
                info.setRva(rva);
                info.setEntropy(entropy);
                info.setCharacteristics(characteristics != null ? characteristics : "");

                result.getSections().add(info);
            }
        } else {
            logger.warn("SectionTable is null for file: {}", peFile.getName());
        }

        // Debug/logging
        logger.info("PE Machine Type: {}", result.getMachineType());
        logger.info("Entry Point: 0x{}", Long.toHexString(result.getEntryPoint()));
        logger.info("Image Base: 0x{}", Long.toHexString(result.getImageBase()));
        logger.info("Subsystem: {}", result.getSubsystem());
        logger.info("Sections count: {}", result.getSections().size());
        logger.info("📄 Parsed Filename: {}", result.getFilename()); // ✅ extra verification log

        // Optional: list OptionalHeader method names (debug)
        if (optional != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("OptionalHeader methods: ");
            for (Method m : optional.getClass().getMethods()) {
                sb.append(m.getName()).append(", ");
            }
            logger.debug(sb.toString());
        }

        return result;
    }


    // -------------------------
    // Upload helper
    // -------------------------

    public static PEFunctionResult parseFunctionsFromUpload(MultipartFile file) throws Exception {
        File tempFile = convertToFile(file);
        try {
            return new PEFunctionResult(
                    extractImportedFunctions(tempFile),
                    extractExportedFunctions(tempFile)
            );
        } finally {
            if (tempFile != null && tempFile.exists()) tempFile.delete();
        }
    }

    private static File convertToFile(MultipartFile multipartFile) throws IOException {
        File convFile = File.createTempFile("upload_", ".bin");
        try (FileOutputStream fos = new FileOutputStream(convFile)) {
            fos.write(multipartFile.getBytes());
        }
        return convFile;
    }

    // -------------------------
    // Reflection helpers (legacy/utility)
    // -------------------------

    public static String tryInvokeAsString(Object target, String... candidates) {
        Object val = safeInvokeObject(target, candidates);
        return val == null ? null : String.valueOf(val);
    }

    private static Long tryInvokeLong(Object target, String... candidates) {
        Object val = safeInvokeObject(target, candidates);
        if (val == null) return null;
        if (val instanceof Number) return ((Number) val).longValue();
        try { return Long.parseLong(String.valueOf(val)); } catch (NumberFormatException ignored) { return null; }
    }

    private static Double tryInvokeDouble(Object target, String... candidates) {
        Object val = safeInvokeObject(target, candidates);
        if (val == null) return null;
        if (val instanceof Number) return ((Number) val).doubleValue();
        try { return Double.parseDouble(String.valueOf(val)); } catch (NumberFormatException ignored) { return null; }
    }

    private static Object safeInvokeObject(Object target, String... candidates) {
        if (target == null) return null;
        for (String m : candidates) {
            try {
                Method mm = target.getClass().getMethod(m);
                return mm.invoke(target);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ignored) {
            }
        }
        return null;
    }

    private static String safeToString(Object o) {
        if (o == null) return null;
        try { return o.toString(); } catch (Throwable t) { return null; }
    }

    private static String extractNameFromImportObject(Object imp) {
        if (imp == null) return null;
        String[] candidates = {"getName", "name", "getImportName", "importName", "toString"};
        for (String m : candidates) {
            try {
                Method mm = imp.getClass().getMethod(m);
                Object ret = mm.invoke(imp);
                if (ret != null) {
                    String s = String.valueOf(ret);
                    if (!s.isEmpty()) return s;
                }
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ignored) {}
        }
        return safeToString(imp);
    }

    private static String extractOrdinalFromImportObject(Object imp) {
        if (imp == null) return null;
        String[] candidates = {"ordinal", "getOrdinal", "getOrdinalNumber"};
        for (String m : candidates) {
            try {
                Method mm = imp.getClass().getMethod(m);
                Object ret = mm.invoke(imp);
                if (ret != null) return String.valueOf(ret);
            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException ignored) {}
        }
        return null;
    }

    private static String safeInvokeString(Object target, String... candidates) {
        return tryInvokeAsString(target, candidates);
    }

    // -------------------------
    // DTOs
    // -------------------------

    public static class PEFunctionResult {
        private List<String> importedFunctions;
        private List<String> exportedFunctions;
        private String filename; // ✅ Add this field
        
        public PEFunctionResult() {}
        
        public PEFunctionResult(List<String> importedFunctions, List<String> exportedFunctions) {
            this.importedFunctions = importedFunctions;
            this.exportedFunctions = exportedFunctions;
        }
        
        public PEFunctionResult(List<String> importedFunctions, List<String> exportedFunctions, String filename) {
            this.importedFunctions = importedFunctions;
            this.exportedFunctions = exportedFunctions;
            this.filename = filename;
        }
        
        public List<String> getImportedFunctions() {
            return importedFunctions;
        }

        public void setImportedFunctions(List<String> importedFunctions) {
            this.importedFunctions = importedFunctions;
        }

        public List<String> getExportedFunctions() {
            return exportedFunctions;
        }

        public void setExportedFunctions(List<String> exportedFunctions) {
            this.exportedFunctions = exportedFunctions;
        }

        public String getFilename() { // ✅ Add getter
            return filename;
        }

        public void setFilename(String filename) { // ✅ Add setter
            this.filename = filename;
        }
    }


    public static class PEHeaderResult {
        private String machineType;
        private Long timestamp;
        private int numSections;
        private String characteristics;
        private Long entryPoint;
        private Long imageBase;
        private String subsystem;
        private String dllCharacteristics;
        private String filename;
        private List<PESectionInfo> sections = new ArrayList<>();

        // ✅ Default constructor (fixes "constructor undefined" error)
        public PEHeaderResult() {
            this.filename = "unknown";
            this.machineType = "";
            this.entryPoint = 0L;
            this.imageBase = 0L;
            this.subsystem = "";
            this.sections = new ArrayList<>();
        }

        // ✅ Parameterized constructor (for manual creation)
        public PEHeaderResult(String filename, String machineType, long entryPoint,
                              long imageBase, String subsystem, List<PESectionInfo> sections) {
            this.filename = filename;
            this.machineType = machineType;
            this.entryPoint = entryPoint;
            this.imageBase = imageBase;
            this.subsystem = subsystem;
            this.sections = sections;
        }

        // ✅ Getters & Setters
        public String getMachineType() { return machineType; }
        public void setMachineType(String machineType) { this.machineType = machineType; }

        public Long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

        public int getNumSections() { return numSections; }
        public void setNumSections(int numSections) { this.numSections = numSections; }

        public String getCharacteristics() { return characteristics; }
        public void setCharacteristics(String characteristics) { this.characteristics = characteristics; }

        public Long getEntryPoint() { return entryPoint == null ? 0L : entryPoint; }
        public void setEntryPoint(long entryPoint) { this.entryPoint = entryPoint; }

        public Long getImageBase() { return imageBase == null ? 0L : imageBase; }
        public void setImageBase(long imageBase) { this.imageBase = imageBase; }

        public String getSubsystem() { return subsystem; }
        public void setSubsystem(String subsystem) { this.subsystem = subsystem; }

        public String getDllCharacteristics() { return dllCharacteristics; }
        public void setDllCharacteristics(String dllCharacteristics) { this.dllCharacteristics = dllCharacteristics; }

        public List<PESectionInfo> getSections() { return sections; }
        public void setSections(List<PESectionInfo> sections) { this.sections = sections; }

        public String getFilename() { return filename; }
        public void setFilename(String filename) { this.filename = filename; }
    }


    // -------------------------
    // Packed detection
    // -------------------------

    public static boolean isPacked(PEHeaderResult header) {
        if (header == null || header.getSections() == null || header.getSections().isEmpty()) return false;

        for (PESectionInfo section : header.getSections()) {
            if (section == null) continue;
            String secName = section.getName() != null ? section.getName().trim().toUpperCase() : "";

            // Check 1: Known packer section signatures (UPX, ASPack, MPRESS, etc.)
            if (secName.startsWith("UPX") || secName.startsWith(".UPX") ||
                secName.contains("ASPACK") || secName.contains("MPRESS") ||
                secName.contains("FSG") || secName.contains("MEW") ||
                secName.contains("THEMIDA") || secName.contains("VMP") ||
                secName.contains("PECOMPACT") || secName.startsWith(".NSP")) {
                return true;
            }

            // Check 2: Unpack buffer anomaly (0 raw size with executable virtual size)
            Long raw = section.getRawSize();
            Long vs = section.getVirtualSize();
            String chars = section.getCharacteristics() != null ? section.getCharacteristics().toUpperCase() : "";
            if (chars.contains("EXECUTE") && (raw == null || raw == 0) && (vs != null && vs > 2048)) {
                return true;
            }

            // Check 3: Virtual size vastly exceeding raw size (ratio > 8:1) in executable sections
            if (chars.contains("EXECUTE") && raw != null && raw > 0 && vs != null && ((double) vs / raw > 8.0)) {
                return true;
            }

            // Check 4: Extremely high entropy in executable sections (> 7.4) with substantial size
            Double ent = section.getEntropy();
            if (chars.contains("EXECUTE") && ent != null && ent >= 7.4 && raw != null && raw > 4096) {
                return true;
            }
        }

        return false;
    }
    
    
}
