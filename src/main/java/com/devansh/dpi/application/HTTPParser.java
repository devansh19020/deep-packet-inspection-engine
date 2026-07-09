
package com.devansh.dpi.application;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import com.devansh.dpi.model.HttpInfo;

public class HTTPParser {

    public HttpInfo parse(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return null;
        }

        int headerEnd = findHeaderEnd(payload);

        if (headerEnd == -1) {
            return null;
        }

        int headerLength = headerEnd + 4;

        String headerText = new String(
                payload, 0, headerLength,
                StandardCharsets.ISO_8859_1
        );

        String[] lines = headerText.split("\\r\\n");

        if (lines.length == 0 || lines[0].isBlank()) {
            return null;
        }

        Integer contentLength = parseContentLength(lines);

        if (contentLength == null || contentLength < 0) {
            return null;
        }

        // A declared body must be fully present.
        int availableBodyBytes = payload.length - headerLength;

        if (availableBodyBytes < contentLength) {
            return null;
        }

        String body = new String(
                payload,
                headerLength,
                contentLength,
                StandardCharsets.ISO_8859_1
        );

        String firstLine = lines[0];

        if (firstLine.startsWith("HTTP/")) {
            return parseResponse(
                    firstLine, body, contentLength
            );
        }

        return parseRequest(
                lines, body, contentLength
        );
    }

    private HttpInfo parseRequest(
            String[] lines,
            String body,
            Integer contentLength) {

        String[] parts = lines[0].trim().split("\\s+");

        if (parts.length != 3) {
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
            String line = lines[i];

            if (line.toLowerCase(Locale.ROOT)
                    .startsWith("host:")) {

                host = line.substring(5).trim();
                break;
            }
        }

        return new HttpInfo(
                true,
                method,
                path,
                version,
                host,
                null,
                body,
                contentLength
        );
    }

    private HttpInfo parseResponse(
            String firstLine,
            String body,
            Integer contentLength) {

        String[] parts = firstLine.trim().split("\\s+");

        if (parts.length < 2) {
            return null;
        }

        String version = parts[0];

        try {
            int statusCode = Integer.parseInt(parts[1]);

            return new HttpInfo(
                    false,
                    null,
                    null,
                    version,
                    null,
                    statusCode,
                    body,
                    contentLength
            );

        } catch (NumberFormatException e) {
            return null;
        }
    }

    private Integer parseContentLength(String[] lines) {
        Integer contentLength = null;

        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];

            if (line.isBlank()) {
                continue;
            }

            int colon = line.indexOf(':');

            if (colon <= 0) {
                continue;
            }

            String name = line.substring(0, colon)
                    .trim()
                    .toLowerCase(Locale.ROOT);

            if (!name.equals("content-length")) {
                continue;
            }

            try {
                int value = Integer.parseInt(
                        line.substring(colon + 1).trim()
                );

                if (value < 0) {
                    return null;
                }

                if (contentLength != null
                        && contentLength != value) {
                    return null;
                }

                contentLength = value;

            } catch (NumberFormatException e) {
                return null;
            }
        }

        // No Content-Length means a zero-length body
        // for this simplified parser.
        return contentLength == null ? 0 : contentLength;
    }

    private int findHeaderEnd(byte[] data) {
        for (int i = 0; i <= data.length - 4; i++) {
            if (data[i] == '\r'
                    && data[i + 1] == '\n'
                    && data[i + 2] == '\r'
                    && data[i + 3] == '\n') {
                return i;
            }
        }

        return -1;
    }
}
