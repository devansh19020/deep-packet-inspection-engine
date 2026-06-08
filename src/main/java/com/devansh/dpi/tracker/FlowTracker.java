package com.devansh.dpi.tracker;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.devansh.dpi.parser.ParsedPacket;

public class FlowTracker {

    private final Map<FlowKey, Flow> flows = new HashMap<>();

    public void process(ParsedPacket packet) {

        if (!packet.hasTCP()) {
            return;
        }

        FlowKey key = FlowKey.fromPacket(
                packet.getSourceIp(),
                packet.getDestinationIp(),
                packet.getSourcePort(),
                packet.getDestinationPort(),
                packet.getProtocol()
        );

        long timestamp =
                packet.getRawPacket()
                        .getHeader()
                        .getTimestampSeconds();

        int packetLength =
                packet.getRawPacket()
                        .getHeader()
                        .getCapturedLength();

        Flow flow = flows.get(key);

        if (flow == null) {

            flow = new Flow(
                    key,
                    timestamp,
                    packetLength
            );

            flows.put(key, flow);

        } else {

            flow.update(
                    timestamp,
                    packetLength
            );
        }
    }

    public int getFlowCount() {
        return flows.size();
    }

    public Collection<Flow> getFlows() {
        return flows.values();
    }
}