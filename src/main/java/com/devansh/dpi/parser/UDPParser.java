package com.devansh.dpi.parser;

import com.devansh.dpi.model.IPv4Packet;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.model.UDPPacket;
import com.devansh.dpi.util.ByteUtils;

public class UDPParser {

    public UDPPacket parse(
            RawPacket packet,
            IPv4Packet ipPacket) {

        byte[] data = packet.getData();

        int udpOffset =
                14 + ipPacket.getHeaderLength();

        // UDP header requires at least 8 bytes.
        if (udpOffset < 0 ||
                udpOffset + 8 > data.length) {
            return null;
        }

        int sourcePort =
                ByteUtils.readUnsignedShort(data, udpOffset);

        int destinationPort =
                ByteUtils.readUnsignedShort(data, udpOffset + 2);

        int length =
                ByteUtils.readUnsignedShort(data, udpOffset + 4);

        int checksum =
                ByteUtils.readUnsignedShort(data, udpOffset + 6);

        // A valid UDP length includes its 8-byte header.
        if (length < 8) {
            return null;
        }

        return new UDPPacket(
                sourcePort,
                destinationPort,
                length,
                checksum,
                udpOffset + 8
        );
    }
}