package com.devansh.dpi.parser;


import com.devansh.dpi.model.*;
import com.devansh.dpi.util.ByteUtils;

public class IPv4Parser {

    public IPv4Packet parse(
            RawPacket packet){

        byte[] data =
                packet.getData();

        int ipOffset = 14;

        int firstByte =
                data[ipOffset] & 0xFF;

        int version =
                firstByte >> 4;

        int ihl =
                firstByte & 0x0F;

        int headerLength =
                ihl * 4;

        int ttl =
                data[ipOffset+8] & 0xFF;

        int protocol =
                data[ipOffset+9] & 0xFF;

        String source =
                ByteUtils.readIPv4(
                        data,
                        ipOffset+12);

        String destination =
                ByteUtils.readIPv4(
                        data,
                        ipOffset+16);

        return new IPv4Packet(

                version,

                headerLength,

                ttl,

                protocol,

                source,

                destination
        );

    }

}
