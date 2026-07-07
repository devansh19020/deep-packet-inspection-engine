package com.devansh.dpi.config;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;

public class RuleConfigLoader {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public DpiConfig load(String filePath) throws IOException {

        Path path = Path.of(filePath);

        if (!Files.isRegularFile(path)) {
            throw new IOException(
                    "Rules configuration file not found: " + filePath
            );
        }

        DpiConfig config;

        try (var inputStream = Files.newInputStream(path)) {
            config = objectMapper.readValue(
                    inputStream,
                    DpiConfig.class
            );
        }

        if (config == null) {
            throw new IOException("Rules configuration is empty.");
        }

        // Normalize missing or null lists.
        if (config.getSuspiciousDomains() == null) {
            config.setSuspiciousDomains(new ArrayList<>());
        }

        if (config.getSuspiciousPorts() == null) {
            config.setSuspiciousPorts(new ArrayList<>());
        }

        if (config.getSuspiciousHttpPaths() == null) {
            config.setSuspiciousHttpPaths(new ArrayList<>());
        }

        validate(config);

        return config;
    }

    private void validate(DpiConfig config) throws IOException {

        for (Integer port : config.getSuspiciousPorts()) {
            if (port == null || port < 1 || port > 65535) {
                throw new IOException(
                        "Invalid suspicious port: " + port
                );
            }
        }

        for (String domain : config.getSuspiciousDomains()) {
            if (domain == null || domain.isBlank()) {
                throw new IOException(
                        "Suspicious domains cannot be blank."
                );
            }
        }

        for (String path : config.getSuspiciousHttpPaths()) {
            if (path == null || path.isBlank()) {
                throw new IOException(
                        "Suspicious HTTP paths cannot be blank."
                );
            }
        }
    }
}