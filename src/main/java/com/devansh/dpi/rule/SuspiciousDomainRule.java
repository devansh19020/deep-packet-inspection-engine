package com.devansh.dpi.rule;

import com.devansh.dpi.inspection.InspectionResult;

import java.util.HashSet;
import java.util.Set;

public class SuspiciousDomainRule implements Rule {

    private final Set<String> suspiciousDomains;

    public SuspiciousDomainRule(
            Set<String> suspiciousDomains) {

        this.suspiciousDomains =
                new HashSet<>(suspiciousDomains);
    }

    @Override
    public SecurityAlert evaluate(
            InspectionResult result) {

        String domain = extractDomain(result);

        if (domain == null) {
            return null;
        }

        if (suspiciousDomains.contains(
                domain.toLowerCase())) {

            return new SecurityAlert(
                    "Suspicious Domain Rule",
                    "Suspicious domain detected: " +
                            domain,
                    "HIGH"
            );
        }

        return null;
    }

    private String extractDomain(
            InspectionResult result) {

        /*
         * First try HTTP Host
         */
        if (result.hasHttp() &&
                result.getHttpInfo().getHost() != null) {

            return result.getHttpInfo()
                    .getHost();
        }

        /*
         * Then try TLS SNI
         */
        if (result.hasTls() &&
                result.getTlsInfo().hasServerName()) {

            return result.getTlsInfo()
                    .getServerName();
        }

        return null;
    }
}