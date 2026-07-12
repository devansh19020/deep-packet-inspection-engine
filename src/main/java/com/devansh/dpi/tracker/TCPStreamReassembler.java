
package com.devansh.dpi.tracker;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.devansh.dpi.model.TCPStreamData;
import com.devansh.dpi.parser.ParsedPacket;

public class TCPStreamReassembler {

    private static final long SEQ_MASK = 0xFFFF_FFFFL;

    private static final int MAX_TRACKED_DIRECTIONS = 8192;
    private static final int MAX_PENDING_SEGMENTS = 1024;
    private static final int MAX_PENDING_BYTES = 1024 * 1024;
    private static final long IDLE_TIMEOUT_MS = 5 * 60 * 1000L;

    private final Map<DirectionKey, StreamState> streams =
            new HashMap<>();

    private final Map<FlowKey, ConnectionState> connections =
            new HashMap<>();

    private final Set<FlowKey> closedFlows = new HashSet<>();

    public synchronized List<TCPStreamData> process(
            ParsedPacket packet) {

        List<TCPStreamData> output = new ArrayList<>();

        if (packet == null || !packet.hasTCP() || !packet.hasIPv4()) {
            return output;
        }

        long now = System.currentTimeMillis();
        cleanupExpired(now);

        int flags = packet.getTcpPacket().getFlags();

        boolean syn = (flags & 0x02) != 0;
        boolean fin = (flags & 0x01) != 0;
        boolean rst = (flags & 0x04) != 0;

        FlowKey flowKey = FlowKey.fromPacket(
                packet.getSourceIp(),
                packet.getDestinationIp(),
                packet.getSourcePort(),
                packet.getDestinationPort(),
                packet.getProtocol()
        );

        boolean forward =
                packet.getSourceIp().equals(flowKey.getSourceIp())
                && packet.getSourcePort() == flowKey.getSourcePort();

        DirectionKey key = new DirectionKey(flowKey, forward);

        if (rst) {
            // RST terminates the connection immediately.
            removeFlowState(flowKey);
            closedFlows.add(flowKey);
            return output;
        }


        if (syn) {
            StreamState existing = streams.get(key);

            long synPayloadSequence = addSequence(
                    normalizeSequence(packet.getSequenceNumber()), 1
            );

            boolean isNewConnection =
                    existing != null
                    && existing.initialized
                    && existing.initialSequence != synPayloadSequence;

            if (isNewConnection) {
                removeFlowState(flowKey);
            }
        }


        ensureCapacity(flowKey);

        ConnectionState connection = connections.computeIfAbsent(
                flowKey, ignored -> new ConnectionState()
        );

        connection.lastUpdated = now;

        StreamState state = streams.computeIfAbsent(
                key, ignored -> new StreamState()
        );

        state.lastUpdated = now;

        long sequence = normalizeSequence(packet.getSequenceNumber());

        // SYN consumes one sequence number.
        long payloadSequence = addSequence(sequence, syn ? 1 : 0);

        if (syn) {
            boolean retransmittedSyn =
                    state.initialized
                    && state.initialSequence == payloadSequence;

            if (!retransmittedSyn) {
                state.reset(payloadSequence);
            }
        }

        byte[] payload = packet.getTcpPayload();

        if (!state.initialized && (payload.length > 0 || fin)) {
            // Supports captures that begin mid-connection.
            state.reset(payloadSequence);
        }

        if (state.initialized && payload.length > 0) {
            byte[] assembled = acceptPayload(
                    state, payloadSequence, payload
            );

            if (assembled.length > 0) {
                output.add(new TCPStreamData(
                        flowKey,
                        forward,
                        state.lastEmittedStart,
                        assembled
                ));
            }
        }

        if (fin) {
            if (forward) {
                connection.forwardFinSeen = true;
            } else {
                connection.reverseFinSeen = true;
            }

            if (state.initialized) {
                state.finSequence = addSequence(
                        payloadSequence, payload.length
                );
                state.finSeen = true;
                state.finConsumed =
                        state.expectedSequence == state.finSequence;
            }
        }

        // A FIN may become contiguous after payload processing.
        if (state.finSeen
                && state.expectedSequence == state.finSequence) {
            state.finConsumed = true;
        }

        StreamState forwardState =
                streams.get(new DirectionKey(flowKey, true));

        StreamState reverseState =
                streams.get(new DirectionKey(flowKey, false));

        boolean forwardClosed =
                !connection.forwardFinSeen
                || (forwardState != null && forwardState.finConsumed);

        boolean reverseClosed =
                !connection.reverseFinSeen
                || (reverseState != null && reverseState.finConsumed);

        if (connection.forwardFinSeen
                && connection.reverseFinSeen
                && forwardClosed
                && reverseClosed) {
            removeFlowState(flowKey);
            closedFlows.add(flowKey);
        }

        return output;
    }

    /*
     * Returns a copy of flows closed since the last call.
     * Main should pass these to TCPApplicationBuffer.removeFlow().
     */
    public synchronized Set<FlowKey> drainClosedFlows() {
        Set<FlowKey> result = new HashSet<>(closedFlows);
        closedFlows.clear();
        return result;
    }

    public synchronized int getTrackedDirectionCount() {
        return streams.size();
    }

    private byte[] acceptPayload(
            StreamState state,
            long sequence,
            byte[] incoming) {

        long expected = state.expectedSequence;
        int distance = sequenceDistance(sequence, expected);

        if (distance < 0) {
            long overlap = -(long) distance;

            // Entire payload has already been emitted.
            if (overlap >= incoming.length) {
                return new byte[0];
            }

            int skip = (int) overlap;
            incoming = Arrays.copyOfRange(
                    incoming, skip, incoming.length
            );

            sequence = expected;
            distance = 0;
        }

        if (distance > 0) {
            addPending(state, sequence, incoming);
            return new byte[0];
        }

        long chunkStart = state.expectedSequence;
        ByteArrayOutputStream assembled = new ByteArrayOutputStream();

        assembled.write(incoming, 0, incoming.length);
        state.expectedSequence = addSequence(
                state.expectedSequence, incoming.length
        );

        drainPending(state, assembled);

        state.lastEmittedStart = chunkStart;

        return assembled.toByteArray();
    }

    private void drainPending(
            StreamState state,
            ByteArrayOutputStream assembled) {

        while (!state.pending.isEmpty()) {
            Long selectedSequence = null;
            byte[] selectedPayload = null;
            int selectedDistance = Integer.MIN_VALUE;

            Iterator<Map.Entry<Long, byte[]>> iterator =
                    state.pending.entrySet().iterator();

            while (iterator.hasNext()) {
                Map.Entry<Long, byte[]> entry = iterator.next();

                int distance = sequenceDistance(
                        entry.getKey(), state.expectedSequence
                );

                long endDistance =
                        (long) distance + entry.getValue().length;

                // This segment is entirely behind the current point.
                if (endDistance <= 0) {
                    state.pendingBytes -= entry.getValue().length;
                    iterator.remove();
                    continue;
                }

                // Eligible if it starts at or before expected and
                // still contains at least one unseen byte.
                if (distance <= 0 && endDistance > 0) {
                    if (selectedSequence == null
                            || distance > selectedDistance) {
                        selectedSequence = entry.getKey();
                        selectedPayload = entry.getValue();
                        selectedDistance = distance;
                    }
                }
            }

            if (selectedSequence == null) {
                // A gap remains.
                break;
            }

            state.pending.remove(selectedSequence);
            state.pendingBytes -= selectedPayload.length;

            int skip = Math.max(0, -selectedDistance);

            if (skip >= selectedPayload.length) {
                continue;
            }

            int newBytes = selectedPayload.length - skip;

            assembled.write(
                    selectedPayload, skip, newBytes
            );

            state.expectedSequence = addSequence(
                    state.expectedSequence, newBytes
            );
        }
    }

    private void addPending(
            StreamState state,
            long sequence,
            byte[] payload) {

        // First-seen policy for duplicate segments with the same start.
        if (state.pending.containsKey(sequence)) {
            return;
        }

        if (state.pending.size() >= MAX_PENDING_SEGMENTS
                || (long) state.pendingBytes + payload.length
                        > MAX_PENDING_BYTES) {
            // Resource protection: discard this out-of-order segment.
            return;
        }

        state.pending.put(sequence, payload.clone());
        state.pendingBytes += payload.length;
    }


    private void cleanupExpired(long now) {
        List<FlowKey> expired = new ArrayList<>();

        for (Map.Entry<FlowKey, ConnectionState> entry
                : connections.entrySet()) {

            if (now - entry.getValue().lastUpdated > IDLE_TIMEOUT_MS) {
                expired.add(entry.getKey());
            }
        }

        for (FlowKey flowKey : expired) {
            removeFlowState(flowKey);
            closedFlows.add(flowKey);
        }
    }


    private void ensureCapacity(FlowKey incomingFlow) {
        if (streams.containsKey(new DirectionKey(incomingFlow, true))
                || streams.containsKey(new DirectionKey(incomingFlow, false))) {
            return;
        }

        if (streams.size() < MAX_TRACKED_DIRECTIONS) {
            return;
        }

        FlowKey oldestFlow = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<FlowKey, ConnectionState> entry
                : connections.entrySet()) {
            if (entry.getValue().lastUpdated < oldestTime) {
                oldestTime = entry.getValue().lastUpdated;
                oldestFlow = entry.getKey();
            }
        }

        if (oldestFlow != null) {
            removeFlowState(oldestFlow);
            closedFlows.add(oldestFlow);
        }
    }

    private void removeFlowState(FlowKey flowKey) {
        streams.remove(new DirectionKey(flowKey, true));
        streams.remove(new DirectionKey(flowKey, false));
        connections.remove(flowKey);
    }

    private static long normalizeSequence(long sequence) {
        return sequence & SEQ_MASK;
    }

    private static long addSequence(long sequence, long amount) {
        return (sequence + amount) & SEQ_MASK;
    }

    /*
     * Signed modular distance. Correct for TCP windows smaller
     * than half the 32-bit sequence space.
     */
    private static int sequenceDistance(long a, long b) {
        return (int) ((a - b) & SEQ_MASK);
    }

    private record DirectionKey(
            FlowKey flowKey,
            boolean forwardDirection) {
    }

    private static class ConnectionState {
        private boolean forwardFinSeen;
        private boolean reverseFinSeen;
        private long lastUpdated = System.currentTimeMillis();
    }

    private static class StreamState {
        private boolean initialized;
        private long initialSequence;
        private long expectedSequence;
        private long lastEmittedStart;
        private long lastUpdated = System.currentTimeMillis();

        private long finSequence;
        private boolean finSeen;
        private boolean finConsumed;

        private int pendingBytes;

        private final Map<Long, byte[]> pending = new HashMap<>();

        private void reset(long initialSequence) {
            this.initialized = true;
            this.initialSequence = normalizeSequence(initialSequence);
            this.expectedSequence = this.initialSequence;
            this.lastEmittedStart = this.initialSequence;

            this.pending.clear();
            this.pendingBytes = 0;

            this.finSeen = false;
            this.finConsumed = false;
        }
    }
}
