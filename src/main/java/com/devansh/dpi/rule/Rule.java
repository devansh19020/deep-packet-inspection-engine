package com.devansh.dpi.rule;

import com.devansh.dpi.inspection.InspectionResult;

public interface Rule {

    SecurityAlert evaluate(
            InspectionResult result
    );
}