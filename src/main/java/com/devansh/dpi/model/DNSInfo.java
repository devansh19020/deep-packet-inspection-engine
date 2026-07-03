package com.devansh.dpi.model;

public class DNSInfo {

    private final int transactionId;
    private final boolean response;
    private final int responseCode;
    private final int questionCount;
    private final int answerCount;
    private final String queryName;
    private final String recordType;

    public DNSInfo(
            int transactionId,
            boolean response,
            int responseCode,
            int questionCount,
            int answerCount,
            String queryName,
            String recordType) {

        this.transactionId = transactionId;
        this.response = response;
        this.responseCode = responseCode;
        this.questionCount = questionCount;
        this.answerCount = answerCount;
        this.queryName = queryName;
        this.recordType = recordType;
    }

    public int getTransactionId() {
        return transactionId;
    }

    public boolean isResponse() {
        return response;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public int getQuestionCount() {
        return questionCount;
    }

    public int getAnswerCount() {
        return answerCount;
    }

    public String getQueryName() {
        return queryName;
    }

    public String getRecordType() {
        return recordType;
    }
}