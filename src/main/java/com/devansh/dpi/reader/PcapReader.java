package com.devansh.dpi.reader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import com.devansh.dpi.model.PcapGlobalHeader;
import com.devansh.dpi.model.PcapPacketHeader;
import com.devansh.dpi.model.RawPacket;

public class PcapReader implements AutoCloseable {

    // PCAP Magic Numbers
    private static final int MAGIC_USEC_BE = 0xA1B2C3D4;
    private static final int MAGIC_USEC_LE = 0xD4C3B2A1;
    private static final int MAGIC_NSEC_BE = 0xA1B23C4D;
    private static final int MAGIC_NSEC_LE = 0x4D3CB2A1;

    private FileChannel channel;

    private PcapGlobalHeader globalHeader;

    private ByteOrder byteOrder;

    private final ByteBuffer packetHeaderBuffer =
            ByteBuffer.allocate(16);

    public void open(String fileName) throws IOException {

        channel = FileChannel.open(
                Path.of(fileName),
                StandardOpenOption.READ
        );

        ByteBuffer globalHeaderBuffer =
                ByteBuffer.allocate(24);

        while (globalHeaderBuffer.hasRemaining()) {

            if (channel.read(globalHeaderBuffer) == -1) {

                throw new IOException(
                        "Unexpected end of file while reading global header."
                );
            }
        }

        globalHeaderBuffer.flip();

        /*
         * Read the first 4 bytes as raw bytes.
         * We must determine byte order before reading
         * the rest of the PCAP global header.
         */
        byte[] magicBytes = new byte[4];

        globalHeaderBuffer.get(magicBytes);

        byteOrder = determineByteOrder(magicBytes);

        /*
         * Rewind and read the complete global header
         * using the detected byte order.
         */
        globalHeaderBuffer.rewind();
        globalHeaderBuffer.order(byteOrder);

        globalHeader = new PcapGlobalHeader(

                globalHeaderBuffer.getInt(),

                globalHeaderBuffer.getShort(),

                globalHeaderBuffer.getShort(),

                globalHeaderBuffer.getInt(),

                globalHeaderBuffer.getInt(),

                globalHeaderBuffer.getInt(),

                globalHeaderBuffer.getInt()
        );
    }

    public RawPacket readNextPacket() throws IOException {

        if (channel == null) {

            throw new IllegalStateException(
                    "PCAP reader has not been opened."
            );
        }

        packetHeaderBuffer.clear();

        int bytesRead = 0;

        while (packetHeaderBuffer.hasRemaining()) {

            int n = channel.read(packetHeaderBuffer);

            if (n == -1) {

                if (bytesRead == 0) {

                    return null;
                }

                throw new IOException(
                        "Unexpected EOF while reading packet header."
                );
            }

            bytesRead += n;
        }

        packetHeaderBuffer.flip();

        // IMPORTANT: Packet headers use the same byte order
        // as the global header.
        packetHeaderBuffer.order(byteOrder);

        long tsSec =
                Integer.toUnsignedLong(
                        packetHeaderBuffer.getInt()
                );

        long tsFraction =
                Integer.toUnsignedLong(
                        packetHeaderBuffer.getInt()
                );

        int capturedLength =
                packetHeaderBuffer.getInt();

        int originalLength =
                packetHeaderBuffer.getInt();

        if (capturedLength < 0 ||
                capturedLength > globalHeader.getSnapLen()) {

            throw new IOException(
                    "Invalid packet length: " +
                            capturedLength
            );
        }

        ByteBuffer packetBuffer =
                ByteBuffer.allocate(capturedLength);

        while (packetBuffer.hasRemaining()) {

            if (channel.read(packetBuffer) == -1) {

                throw new IOException(
                        "Unexpected EOF while reading packet data."
                );
            }
        }

        packetBuffer.flip();

        byte[] data =
                new byte[capturedLength];

        packetBuffer.get(data);

        PcapPacketHeader packetHeader =
                new PcapPacketHeader(
                        tsSec,
                        tsFraction,
                        capturedLength,
                        originalLength
                );

        return new RawPacket(packetHeader, data);
    }

    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    private ByteOrder determineByteOrder(
            byte[] magicBytes) throws IOException {

        int magicBigEndian =
                ByteBuffer.wrap(magicBytes)
                        .order(ByteOrder.BIG_ENDIAN)
                        .getInt();

        if (magicBigEndian == MAGIC_USEC_BE ||
                magicBigEndian == MAGIC_NSEC_BE) {

            return ByteOrder.BIG_ENDIAN;
        }

        if (magicBigEndian == MAGIC_USEC_LE ||
                magicBigEndian == MAGIC_NSEC_LE) {

            return ByteOrder.LITTLE_ENDIAN;
        }

        throw new IOException(
                "Invalid PCAP file. Unsupported magic number."
        );
    }

    @Override
    public void close() throws IOException {

        if (channel != null && channel.isOpen()) {

            channel.close();
        }
    }
}