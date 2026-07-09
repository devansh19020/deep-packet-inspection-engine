
package com.devansh.dpi.tracker;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import com.devansh.dpi.application.HTTPParser;
import com.devansh.dpi.model.HttpInfo;
import com.devansh.dpi.model.TCPStreamData;

public class TCPApplicationBuffer {

    private static final int MAX_BUFFER_SIZE = 1024 * 1024;
    private static final int MAX_TRACKED_STREAMS = 4096;
    private static final long IDLE_TIMEOUT_MS = 5 * 60 * 1000L;

    private final HTTPParser httpParser = new HTTPParser();

    private final Map<StreamKey, BufferState> buffers =
            new HashMap<>();

    public List<HttpInfo> process(TCPStreamData chunk) {
        List<HttpInfo> completedMessages = new ArrayList<>();

        long now = System.currentTimeMillis();
        cleanupExpiredBuffers(now);

        StreamKey key = new StreamKey(
                chunk.getFlowKey(),
                chunk.isForwardDirection()
        );

        BufferState state = buffers.get(key);

        if (state == null) {
            // Make room before adding a new stream.
            if (buffers.size() >= MAX_TRACKED_STREAMS) {
                evictLeastRecentlyUsed();
            }

            state = new BufferState();
            buffers.put(key, state);
        }

        state.lastUpdated = now;

        byte[] incoming = chunk.getData();

        if ((long) state.buffer.size() + incoming.length
                > MAX_BUFFER_SIZE) {
            // Drop this stream's application buffer if it grows too large.
            buffers.remove(key);
            return completedMessages;
        }

        state.buffer.write(incoming, 0, incoming.length);

        byte[] accumulated = state.buffer.toByteArray();

        while (accumulated.length > 0) {
            int headerEnd = findHeaderEnd(accumulated);

            if (headerEnd == -1) {
                break;
            }

            int headerLength = headerEnd + 4;

            byte[] header = Arrays.copyOfRange(
                    accumulated, 0, headerLength
            );

            int contentLength = parseContentLength(header);

            if (contentLength < 0
                    || contentLength > MAX_BUFFER_SIZE) {
                // Invalid framing: discard the incomplete stream data.
                buffers.remove(key);
                return completedMessages;
            }

            long totalLength = (long) headerLength + contentLength;

            if (accumulated.length < totalLength) {
                // Header is complete, but the body has not fully arrived.
                break;
            }

            int messageLength = (int) totalLength;

            byte[] completeMessage = Arrays.copyOfRange(
                    accumulated, 0, messageLength
            );

            HttpInfo httpInfo = httpParser.parse(completeMessage);

            if (httpInfo != null) {
                completedMessages.add(httpInfo);
            }

            // Preserve data belonging to a subsequent HTTP message.
            accumulated = Arrays.copyOfRange(
                    accumulated, messageLength, accumulated.length
            );
        }

        state.buffer.reset();

        if (accumulated.length > 0) {
            state.buffer.write(accumulated, 0, accumulated.length);
        }

        // Keep the timestamp fresh after successful processing.
        state.lastUpdated = System.currentTimeMillis();

        return completedMessages;
    }

    private void cleanupExpiredBuffers(long now) {
        buffers.entrySet().removeIf(entry ->
                now - entry.getValue().lastUpdated > IDLE_TIMEOUT_MS
        );
    }

    private void evictLeastRecentlyUsed() {
        StreamKey oldestKey = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<StreamKey, BufferState> entry
                : buffers.entrySet()) {

            if (entry.getValue().lastUpdated < oldestTime) {
                oldestTime = entry.getValue().lastUpdated;
                oldestKey = entry.getKey();
            }
        }

        if (oldestKey != null) {
            buffers.remove(oldestKey);
        }
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

    private int parseContentLength(byte[] header) {
        String text = new String(
                header, StandardCharsets.ISO_8859_1
        );

        String[] lines = text.split("\\r\\n");
        Integer contentLength = null;

        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');

            if (colon <= 0) {
                continue;
            }

            String name = lines[i].substring(0, colon)
                    .trim()
                    .toLowerCase(Locale.ROOT);

            if (!name.equals("content-length")) {
                continue;
            }

            try {
                int value = Integer.parseInt(
                        lines[i].substring(colon + 1).trim()
                );

                if (value < 0) {
                    return -1;
                }

                if (contentLength != null
                        && contentLength != value) {
                    return -1;
                }

                contentLength = value;

            } catch (NumberFormatException e) {
                return -1;
            }
        }

        return contentLength == null ? 0 : contentLength;
    }

    private static class BufferState {
        private final ByteArrayOutputStream buffer =
                new ByteArrayOutputStream();

        private long lastUpdated = System.currentTimeMillis();
    }

    private static class StreamKey {
        private final FlowKey flowKey;
        private final boolean forwardDirection;

        private StreamKey(
                FlowKey flowKey,
                boolean forwardDirection) {
            this.flowKey = flowKey;
            this.forwardDirection = forwardDirection;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (!(obj instanceof StreamKey)) return false;

            StreamKey other = (StreamKey) obj;

            return forwardDirection == other.forwardDirection
                    && Objects.equals(flowKey, other.flowKey);
        }

        @Override
        public int hashCode() {
            return Objects.hash(flowKey, forwardDirection);
        }
    }
}
