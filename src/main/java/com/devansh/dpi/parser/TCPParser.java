package com.devansh.dpi.parser;

import com.devansh.dpi.model.*;
import com.devansh.dpi.util.ByteUtils;

public class TCPParser {

    public TCPPacket parse(
            RawPacket packet,
            IPv4Packet ipPacket){

        byte[] data = packet.getData();

        int tcpOffset =
                14 + ipPacket.getHeaderLength();

        int srcPort =
                ByteUtils.readUnsignedShort(data,tcpOffset);

        int dstPort =
                ByteUtils.readUnsignedShort(data,tcpOffset+2);

        long sequence =
                ByteUtils.readUnsignedInt(data,tcpOffset+4);

        long acknowledgement =
                ByteUtils.readUnsignedInt(data,tcpOffset+8);

        int dataOffset =
                ((data[tcpOffset+12] & 0xFF) >> 4);

        int headerLength =
                dataOffset * 4;

        int flags =
                data[tcpOffset+13] & 0xFF;

        int payloadOffset =
                tcpOffset +
                        headerLength;

        return new TCPPacket(

                srcPort,

                dstPort,

                sequence,

                acknowledgement,

                headerLength,

                flags,

                payloadOffset
        );

    }

}