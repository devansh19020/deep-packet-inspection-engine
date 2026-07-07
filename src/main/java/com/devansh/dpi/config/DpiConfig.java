package com.devansh.dpi.config;

import java.util.ArrayList;
import java.util.List;

public class DpiConfig {

    private List<String> suspiciousDomains = new ArrayList<>();
    private List<Integer> suspiciousPorts = new ArrayList<>();
    private List<String> suspiciousHttpPaths = new ArrayList<>();

    public DpiConfig() {
    }

    public List<String> getSuspiciousDomains() {
        return suspiciousDomains;
    }

    public void setSuspiciousDomains(List<String> suspiciousDomains) {
        this.suspiciousDomains = suspiciousDomains;
    }

    public List<Integer> getSuspiciousPorts() {
        return suspiciousPorts;
    }

    public void setSuspiciousPorts(List<Integer> suspiciousPorts) {
        this.suspiciousPorts = suspiciousPorts;
    }

    public List<String> getSuspiciousHttpPaths() {
        return suspiciousHttpPaths;
    }

    public void setSuspiciousHttpPaths(List<String> suspiciousHttpPaths) {
        this.suspiciousHttpPaths = suspiciousHttpPaths;
    }
}