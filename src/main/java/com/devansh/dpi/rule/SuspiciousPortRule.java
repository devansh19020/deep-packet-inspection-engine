package com.devansh.dpi.rule;

import java.util.HashSet;
import java.util.Set;

import com.devansh.dpi.inspection.InspectionResult;

public class SuspiciousPortRule implements Rule {

    private final Set<Integer> suspiciousPorts;

    public SuspiciousPortRule(Set<Integer> suspiciousPorts) {

        this.suspiciousPorts =
                new HashSet<>(suspiciousPorts);
    }

    @Override
    public SecurityAlert evaluate(
            InspectionResult result) {

        if (!result.getPacket().hasTCP()) {
            return null;
        }

        int destinationPort =
                result.getPacket()
                        .getDestinationPort();

        if (suspiciousPorts.contains(destinationPort)) {

            return new SecurityAlert(
                    "Suspicious Port Rule",
                    "Connection detected to suspicious port: "
                            + destinationPort,
                    "MEDIUM"
            );
        }

        return null;
    }
}