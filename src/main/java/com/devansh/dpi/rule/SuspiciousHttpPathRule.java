package com.devansh.dpi.rule;

import java.util.HashSet;
import java.util.Set;

import com.devansh.dpi.inspection.InspectionResult;

public class SuspiciousHttpPathRule implements Rule {

    private final Set<String> suspiciousPaths;

    public SuspiciousHttpPathRule(
            Set<String> suspiciousPaths) {

        this.suspiciousPaths =
                new HashSet<>();

        for (String path : suspiciousPaths) {

            this.suspiciousPaths.add(
                    path.toLowerCase()
            );
        }
    }

    @Override
    public SecurityAlert evaluate(
            InspectionResult result) {

        if (!result.hasHttp()) {
            return null;
        }

        if (!result.getHttpInfo().isRequest()) {
            return null;
        }

        String path =
                result.getHttpInfo().getPath();

        if (path == null) {
            return null;
        }

        if (suspiciousPaths.contains(
                path.toLowerCase())) {

            return new SecurityAlert(
                    "Suspicious HTTP Path Rule",
                    "Suspicious HTTP path detected: "
                            + path,
                    "MEDIUM"
            );
        }

        return null;
    }
}