package com.devansh.dpi.application;

import com.devansh.dpi.model.DNSInfo;

import java.nio.charset.StandardCharsets;

public class DNSParser {

    public DNSInfo parse(byte[] data) {

        if (data == null || data.length < 12) {
            return null;
        }

        int transactionId = readU16(data, 0);
        int flags = readU16(data, 2);

        boolean response = (flags & 0x8000) != 0;
        int responseCode = flags & 0x000F;

        int questionCount = readU16(data, 4);
        int answerCount = readU16(data, 6);

        // Keep this MVP focused on one-question DNS messages.
        if (questionCount < 1) {
            return new DNSInfo(
                    transactionId,
                    response,
                    responseCode,
                    questionCount,
                    answerCount,
                    null,
                    null
            );
        }

        try {
            NameResult nameResult = readName(data, 12);

            int offset = nameResult.nextOffset;

            if (offset + 4 > data.length) {
                return null;
            }

            int type = readU16(data, offset);

            // Class is normally IN (Internet).
            int recordClass = readU16(data, offset + 2);

            if (recordClass != 1) {
                return null;
            }

            return new DNSInfo(
                    transactionId,
                    response,
                    responseCode,
                    questionCount,
                    answerCount,
                    nameResult.name,
                    getRecordType(type)
            );

        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private NameResult readName(byte[] data, int start) {

        StringBuilder name = new StringBuilder();

        int offset = start;
        int nextOffset = -1;
        int jumps = 0;

        while (true) {

            if (offset >= data.length) {
                throw new IllegalArgumentException(
                        "DNS name exceeds message length"
                );
            }

            int length = data[offset] & 0xFF;

            // Zero-length label terminates the domain name.
            if (length == 0) {
                if (nextOffset == -1) {
                    nextOffset = offset + 1;
                }
                break;
            }

            // DNS compression pointer: first two bits are 11.
            if ((length & 0xC0) == 0xC0) {

                if (offset + 1 >= data.length) {
                    throw new IllegalArgumentException(
                            "Incomplete DNS compression pointer"
                    );
                }

                int pointer =
                        ((length & 0x3F) << 8)
                                | (data[offset + 1] & 0xFF);

                if (pointer >= data.length) {
                    throw new IllegalArgumentException(
                            "Invalid DNS compression pointer"
                    );
                }

                if (nextOffset == -1) {
                    nextOffset = offset + 2;
                }

                offset = pointer;

                // Protect against pointer loops.
                if (++jumps > 20) {
                    throw new IllegalArgumentException(
                            "Too many DNS compression jumps"
                    );
                }

                continue;
            }

            // Reserved label encodings are unsupported.
            if ((length & 0xC0) != 0 || length > 63) {
                throw new IllegalArgumentException(
                        "Invalid DNS label length"
                );
            }

            if (offset + 1 + length > data.length) {
                throw new IllegalArgumentException(
                        "DNS label exceeds message length"
                );
            }

            if (name.length() > 0) {
                name.append('.');
            }

            name.append(
                    new String(
                            data,
                            offset + 1,
                            length,
                            StandardCharsets.US_ASCII
                    )
            );

            offset += 1 + length;
        }

        if (nextOffset < 0) {
            nextOffset = offset + 1;
        }

        return new NameResult(name.toString(), nextOffset);
    }

    private int readU16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private String getRecordType(int type) {

        return switch (type) {
            case 1 -> "A";
            case 2 -> "NS";
            case 5 -> "CNAME";
            case 6 -> "SOA";
            case 12 -> "PTR";
            case 15 -> "MX";
            case 16 -> "TXT";
            case 28 -> "AAAA";
            case 33 -> "SRV";
            case 255 -> "ANY";
            default -> "TYPE" + type;
        };
    }

    private static class NameResult {

        private final String name;
        private final int nextOffset;

        private NameResult(String name, int nextOffset) {
            this.name = name;
            this.nextOffset = nextOffset;
        }
    }
}