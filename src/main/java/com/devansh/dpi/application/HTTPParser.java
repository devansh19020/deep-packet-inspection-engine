package com.devansh.dpi.application;

import java.nio.charset.StandardCharsets;

import com.devansh.dpi.model.HttpInfo;

public class HTTPParser {

    public HttpInfo parse(byte[] payload) {

        if (payload == null || payload.length == 0) {
            return null;
        }

        String data = new String(
                payload,
                StandardCharsets.ISO_8859_1
        );

        String[] lines = data.split("\\r\\n");

        if (lines.length == 0) {
            return null;
        }

        String firstLine = lines[0];

        if (firstLine.startsWith("HTTP/")) {
            return parseResponse(firstLine);
        }

        return parseRequest(lines);
    }

    private HttpInfo parseRequest(String[] lines) {

        String[] parts = lines[0].split(" ");

        if (parts.length < 3) {
            return null;
        }

        String method = parts[0];
        String path = parts[1];
        String version = parts[2];

        if (!version.startsWith("HTTP/")) {
            return null;
        }

        String host = null;

        for (int i = 1; i < lines.length; i++) {

            if (lines[i].toLowerCase()
                    .startsWith("host:")) {

                host = lines[i]
                        .substring(5)
                        .trim();

                break;
            }
        }

        return new HttpInfo(
                true,
                method,
                path,
                version,
                host,
                null
        );
    }

    private HttpInfo parseResponse(String firstLine) {

        String[] parts = firstLine.split(" ");

        if (parts.length < 2) {
            return null;
        }

        String version = parts[0];

        try {

            int statusCode =
                    Integer.parseInt(parts[1]);

            return new HttpInfo(
                    false,
                    null,
                    null,
                    version,
                    null,
                    statusCode
            );

        } catch (NumberFormatException e) {

            return null;
        }
    }
}