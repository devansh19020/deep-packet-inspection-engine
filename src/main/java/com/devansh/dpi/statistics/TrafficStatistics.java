package com.devansh.dpi.statistics;

import com.devansh.dpi.parser.ParsedPacket;

public class TrafficStatistics {

    private long totalPackets;
    private long ipv4Packets;
    private long tcpPackets;
    private long unsupportedPackets;
    private long totalCapturedBytes;
    private long udpPackets;

    public void process(ParsedPacket packet) {

        totalPackets++;

        totalCapturedBytes +=
                packet.getRawPacket()
                        .getHeader()
                        .getCapturedLength();

        if (packet.hasIPv4()) {
            ipv4Packets++;
        } else {
            unsupportedPackets++;
        }

        if (packet.hasTCP()) {
            tcpPackets++;
        }

        if (packet.hasUDP()) {
            udpPackets++;
        }
    }

    public long getTotalPackets() {
        return totalPackets;
    }

    public long getIpv4Packets() {
        return ipv4Packets;
    }

    public long getTcpPackets() {
        return tcpPackets;
    }

    public long getUdpPackets() {
        return udpPackets;
    }

    public long getUnsupportedPackets() {
        return unsupportedPackets;
    }

    public long getTotalCapturedBytes() {
        return totalCapturedBytes;
    }
}