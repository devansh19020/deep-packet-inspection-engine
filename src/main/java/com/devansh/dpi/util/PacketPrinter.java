package com.devansh.dpi.util;

import com.devansh.dpi.parser.ParsedPacket;

public class PacketPrinter {

public void print(ParsedPacket packet) {

    System.out.println("--------------------------------------");

    System.out.println("Source MAC      : " + packet.getSourceMac());
    System.out.println("Destination MAC : " + packet.getDestinationMac());

    if (packet.hasIPv4()) {
        System.out.println("Source IP       : " + packet.getSourceIp());
        System.out.println("Destination IP  : " + packet.getDestinationIp());
        System.out.println("Protocol        : " + packet.getProtocol());
    }

    if (packet.hasTCP()) {
        System.out.println("Transport       : TCP");
        System.out.println("Source Port     : " + packet.getSourcePort());
        System.out.println("Destination Port: " + packet.getDestinationPort());
        System.out.println("Sequence Number : " + packet.getSequenceNumber());
    }

    if (packet.hasUDP()) {
        System.out.println("Transport       : UDP");
        System.out.println("Source Port     : " + packet.getUdpSourcePort());
        System.out.println("Destination Port: " + packet.getUdpDestinationPort());

        System.out.println("UDP Length      : " +
                packet.getUdpPacket().getLength());

        System.out.println("UDP Checksum    : 0x" +
                Integer.toHexString(
                        packet.getUdpPacket().getChecksum()
                ));

        System.out.println("UDP Payload Size: " +
                packet.getUdpPayload().length + " bytes");
    }

    System.out.println("--------------------------------------");
}

}