package com.devansh.dpi.parser;

import com.devansh.dpi.enums.EtherType;
import com.devansh.dpi.enums.TransportProtocol;
import com.devansh.dpi.model.*;

public class PacketParser {

    private final EthernetParser ethernetParser;
    private final IPv4Parser ipv4Parser;
    private final TCPParser tcpParser;

    public PacketParser() {

        ethernetParser = new EthernetParser();
        ipv4Parser = new IPv4Parser();
        tcpParser = new TCPParser();

    }

    public ParsedPacket parse(RawPacket rawPacket) {

        EthernetFrame ethernetFrame =
                ethernetParser.parse(rawPacket);

        ParsedPacket packet =
                new ParsedPacket(rawPacket);

        packet.setEthernetFrame(ethernetFrame);

        if (ethernetFrame.getEtherType() != EtherType.IPV4) {
            return packet;
        }

        IPv4Packet ipv4Packet =
                ipv4Parser.parse(rawPacket);

        packet.setIpv4Packet(ipv4Packet);

        if (ipv4Packet.getProtocol() != TransportProtocol.TCP) {
            return packet;
        }

        TCPPacket tcpPacket =
                tcpParser.parse(rawPacket, ipv4Packet);

        packet.setTcpPacket(tcpPacket);

        return packet;
    }

}