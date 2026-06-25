package com.devansh.dpi.rule;

public class SecurityAlert {

    private final String ruleName;
    private final String message;
    private final String severity;

    public SecurityAlert(
            String ruleName,
            String message,
            String severity) {

        this.ruleName = ruleName;
        this.message = message;
        this.severity = severity;
    }

    public String getRuleName() {
        return ruleName;
    }

    public String getMessage() {
        return message;
    }

    public String getSeverity() {
        return severity;
    }
}