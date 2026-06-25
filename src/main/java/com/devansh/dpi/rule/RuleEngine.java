package com.devansh.dpi.rule;

import com.devansh.dpi.inspection.InspectionResult;

import java.util.ArrayList;
import java.util.List;

public class RuleEngine {

    private final List<Rule> rules;

    public RuleEngine() {
        this.rules = new ArrayList<>();
    }

    public void addRule(Rule rule) {
        rules.add(rule);
    }

    public List<SecurityAlert> evaluate(
            InspectionResult result) {

        List<SecurityAlert> alerts =
                new ArrayList<>();

        for (Rule rule : rules) {

            SecurityAlert alert =
                    rule.evaluate(result);

            if (alert != null) {
                alerts.add(alert);
            }
        }

        return alerts;
    }
}