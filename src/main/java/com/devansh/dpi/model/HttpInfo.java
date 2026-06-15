package com.devansh.dpi.model;

public class HttpInfo {

    private final boolean request;

    private final String method;

    private final String path;

    private final String version;

    private final String host;

    private final Integer statusCode;

    public HttpInfo(
            boolean request,
            String method,
            String path,
            String version,
            String host,
            Integer statusCode) {

        this.request = request;
        this.method = method;
        this.path = path;
        this.version = version;
        this.host = host;
        this.statusCode = statusCode;
    }

    public boolean isRequest() {
        return request;
    }

    public boolean isResponse() {
        return !request;
    }

    public String getMethod() {
        return method;
    }

    public String getPath() {
        return path;
    }

    public String getVersion() {
        return version;
    }

    public String getHost() {
        return host;
    }

    public Integer getStatusCode() {
        return statusCode;
    }
}