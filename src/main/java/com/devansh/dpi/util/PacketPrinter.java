package com.devansh.dpi.util;

import com.devansh.dpi.parser.ParsedPacket;

public class PacketPrinter {

    public void print(ParsedPacket packet) {

        System.out.println("--------------------------------------");

        System.out.println("Source MAC      : " + packet.getSourceMac());

        System.out.println("Destination MAC : " + packet.getDestinationMac());

        if (packet.getIpv4Packet() != null) {

            System.out.println("Source IP       : " + packet.getSourceIp());

            System.out.println("Destination IP  : " + packet.getDestinationIp());

            System.out.println("Protocol        : " + packet.getProtocol());

        }

        if (packet.getTcpPacket() != null) {

            System.out.println("Source Port     : " + packet.getSourcePort());

            System.out.println("Destination Port: " + packet.getDestinationPort());

            System.out.println("Sequence Number : " + packet.getSequenceNumber());

        }

        System.out.println("--------------------------------------");
    }

}