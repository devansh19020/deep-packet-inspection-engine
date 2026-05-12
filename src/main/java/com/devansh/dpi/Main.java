package com.devansh.dpi;

import com.devansh.dpi.model.ParsedPacket;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.parser.PacketParser;
import com.devansh.dpi.reader.PcapReader;

public class Main {

    public static void main(String[] args) {

        String file = "captures/sample.pcap";

        try (PcapReader reader = new PcapReader()) {

            reader.open(file);

            PacketParser parser = new PacketParser();

            RawPacket rawPacket;

            while ((rawPacket = reader.readNextPacket()) != null) {

                ParsedPacket packet = parser.parse(rawPacket);

                if (packet == null) {
                    continue;
                }

                printPacket(packet);

            }

        } catch (Exception e) {

            e.printStackTrace();

        }

    }

    private static void printPacket(ParsedPacket packet) {

        System.out.println("--------------------------------");

        System.out.println("Source MAC      : " + packet.getSourceMac());

        System.out.println("Destination MAC : " + packet.getDestinationMac());

        System.out.println("Source IP       : " + packet.getSourceIp());

        System.out.println("Destination IP  : " + packet.getDestinationIp());

        System.out.println("Source Port     : " + packet.getSourcePort());

        System.out.println("Destination Port: " + packet.getDestinationPort());

        System.out.println();

    }

}