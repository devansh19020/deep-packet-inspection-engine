package com.devansh.dpi.tracker;

import com.devansh.dpi.model.TCPStreamData;
import com.devansh.dpi.parser.ParsedPacket;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class TCPStreamReassembler {

    private final Map<DirectionKey, StreamState> streams =
            new HashMap<>();

    /**
     * Processes one TCP packet and returns any newly
     * reassembled contiguous payload data.
     */
    public synchronized List<TCPStreamData> process(
            ParsedPacket packet) {

        List<TCPStreamData> output = new ArrayList<>();

        if (!packet.hasTCP() || !packet.hasIPv4()) {
            return output;
        }

        byte[] payload = packet.getTcpPayload();

        long sequence = packet.getSequenceNumber();
        int flags = packet.getTcpPacket().getFlags();

        boolean syn = (flags & 0x02) != 0;

        FlowKey flowKey = FlowKey.fromPacket(
                packet.getSourceIp(),
                packet.getDestinationIp(),
                packet.getSourcePort(),
                packet.getDestinationPort(),
                packet.getProtocol()
        );

        boolean forwardDirection =
                packet.getSourceIp().equals(flowKey.getSourceIp())
                && packet.getSourcePort() == flowKey.getSourcePort();

        DirectionKey directionKey =
                new DirectionKey(flowKey, forwardDirection);

        StreamState state = streams.computeIfAbsent(
                directionKey,
                ignored -> new StreamState()
        );

        // A SYN consumes one sequence number, even without payload.
        long payloadSequence = sequence + (syn ? 1 : 0);

        if (syn) {
            state.expectedSequence = payloadSequence;
            state.initialized = true;
            state.pending.clear();
        }

        if (payload.length == 0) {
            return output;
        }

        if (!state.initialized) {
            // Midstream capture: use the first observed payload
            // as the starting point.
            state.expectedSequence = payloadSequence;
            state.initialized = true;
        }

        long expected = state.expectedSequence;

        // Discard bytes that have already been emitted.
        if (payloadSequence < expected) {
            long alreadyConsumed = expected - payloadSequence;

            if (alreadyConsumed >= payload.length) {
                return output;
            }

            int skip = (int) alreadyConsumed;

            byte[] remaining = new byte[payload.length - skip];

            System.arraycopy(
                    payload, skip,
                    remaining, 0,
                    remaining.length
            );

            payload = remaining;
            payloadSequence = expected;
        }

        // Buffer future segments until the missing bytes arrive.
        if (payloadSequence > state.expectedSequence) {
            state.pending.putIfAbsent(payloadSequence, payload);
            return output;
        }

        long chunkStart = state.expectedSequence;
        ByteArrayOutputStream assembled = new ByteArrayOutputStream();

        assembled.writeBytes(payload);
        state.expectedSequence += payload.length;

        // Drain buffered segments that now continue the stream.
        while (!state.pending.isEmpty()) {

            Map.Entry<Long, byte[]> next =
                    state.pending.firstEntry();

            long nextSequence = next.getKey();
            byte[] nextPayload = next.getValue();

            if (nextSequence > state.expectedSequence) {
                break;
            }

            state.pending.pollFirstEntry();

            long overlap =
                    state.expectedSequence - nextSequence;

            if (overlap >= nextPayload.length) {
                continue;
            }

            int skip = (int) Math.max(0, overlap);

            assembled.write(
                    nextPayload,
                    skip,
                    nextPayload.length - skip
            );

            state.expectedSequence +=
                    nextPayload.length - skip;
        }

        byte[] data = assembled.toByteArray();

        if (data.length > 0) {
            output.add(new TCPStreamData(
                    flowKey,
                    forwardDirection,
                    chunkStart,
                    data
            ));
        }

        return output;
    }

    public synchronized int getTrackedDirectionCount() {
        return streams.size();
    }

    private record DirectionKey(
            FlowKey flowKey,
            boolean forwardDirection) {
    }

    private static class StreamState {

        private boolean initialized;
        private long expectedSequence;

        private final TreeMap<Long, byte[]> pending =
                new TreeMap<>();
    }
}