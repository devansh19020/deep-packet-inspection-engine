package com.devansh.dpi;

import com.devansh.dpi.parser.ParsedPacket;
import com.devansh.dpi.model.RawPacket;
import com.devansh.dpi.parser.PacketParser;
import com.devansh.dpi.reader.PcapReader;
import com.devansh.dpi.util.PacketPrinter;

public class Main {

    public static void main(String[] args) {

        PacketParser parser = new PacketParser();

        PacketPrinter printer = new PacketPrinter();

        try (PcapReader reader = new PcapReader()) {

            reader.open("captures/sample.pcap");

            RawPacket rawPacket;

            while ((rawPacket = reader.readNextPacket()) != null) {

                ParsedPacket packet =
                        parser.parse(rawPacket);

                printer.print(packet);

            }

        } catch (Exception e) {

            e.printStackTrace();

        }

    }

}
