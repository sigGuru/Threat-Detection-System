package com.TheSecureSyndicate.threat_detection_backend.dto;

import java.util.List;

public class MLRequest {
    private double entropy;
    private long size;
    private List<String> yaraHits;
    private List<String> imports;

    public double getEntropy() { return entropy; }
    public void setEntropy(double entropy) { this.entropy = entropy; }

    public long getSize() { return size; }
    public void setSize(long size) { this.size = size; }

    public List<String> getYaraHits() { return yaraHits; }
    public void setYaraHits(List<String> yaraHits) { this.yaraHits = yaraHits; }

    public List<String> getImports() { return imports; }
    public void setImports(List<String> imports) { this.imports = imports; }
}
