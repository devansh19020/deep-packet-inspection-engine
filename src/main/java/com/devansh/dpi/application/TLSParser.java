package com.devansh.dpi.application;

import com.devansh.dpi.enums.TlsContentType;
import com.devansh.dpi.model.TlsInfo;

import java.nio.charset.StandardCharsets;

public class TLSParser {

    private static final int TLS_HEADER_LENGTH = 5;

    private static final int HANDSHAKE_TYPE_CLIENT_HELLO = 1;

    private static final int EXTENSION_SERVER_NAME = 0;

    public TlsInfo parse(byte[] payload) {

        if (payload == null ||
                payload.length < TLS_HEADER_LENGTH) {

            return null;
        }

        int contentTypeValue =
                payload[0] & 0xFF;

        TlsContentType contentType =
                TlsContentType.fromValue(
                        contentTypeValue
                );

        if (contentType == TlsContentType.UNKNOWN) {
            return null;
        }

        int majorVersion =
                payload[1] & 0xFF;

        int minorVersion =
                payload[2] & 0xFF;

        int recordLength =
                readUnsignedShort(payload, 3);

        /*
         * Make sure the complete TLS record
         * is available in the TCP payload.
         */
        if (payload.length < TLS_HEADER_LENGTH + recordLength) {

            return new TlsInfo(
                    contentType,
                    majorVersion,
                    minorVersion,
                    recordLength,
                    null
            );
        }

        String serverName = null;

        if (contentType == TlsContentType.HANDSHAKE) {

            serverName =
                    extractSni(
                            payload,
                            TLS_HEADER_LENGTH,
                            TLS_HEADER_LENGTH + recordLength
                    );
        }

        return new TlsInfo(
                contentType,
                majorVersion,
                minorVersion,
                recordLength,
                serverName
        );
    }

    private String extractSni(
            byte[] data,
            int offset,
            int recordEnd) {

        /*
         * Handshake structure:
         *
         * 1 byte  Handshake Type
         * 3 bytes Handshake Length
         */

        if (offset + 4 > recordEnd) {
            return null;
        }

        int handshakeType =
                data[offset] & 0xFF;

        if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) {
            return null;
        }

        int handshakeLength =
                readUnsignedMedium(data, offset + 1);

        int handshakeEnd =
                offset + 4 + handshakeLength;

        /*
         * Never read beyond either:
         * - the handshake
         * - the TLS record
         * - the actual array
         */
        if (handshakeEnd > recordEnd ||
                handshakeEnd > data.length) {

            return null;
        }

        int position = offset + 4;

        /*
         * Client Version
         */
        if (position + 2 > handshakeEnd) {
            return null;
        }

        position += 2;

        /*
         * Random = 32 bytes
         */
        if (position + 32 > handshakeEnd) {
            return null;
        }

        position += 32;

        /*
         * Session ID
         */
        if (position + 1 > handshakeEnd) {
            return null;
        }

        int sessionIdLength =
                data[position] & 0xFF;

        position++;

        if (position + sessionIdLength > handshakeEnd) {
            return null;
        }

        position += sessionIdLength;

        /*
         * Cipher Suites
         */
        if (position + 2 > handshakeEnd) {
            return null;
        }

        int cipherSuitesLength =
                readUnsignedShort(data, position);

        position += 2;

        if (position + cipherSuitesLength > handshakeEnd) {
            return null;
        }

        position += cipherSuitesLength;

        /*
         * Compression Methods
         */
        if (position + 1 > handshakeEnd) {
            return null;
        }

        int compressionMethodsLength =
                data[position] & 0xFF;

        position++;

        if (position + compressionMethodsLength > handshakeEnd) {
            return null;
        }

        position += compressionMethodsLength;

        /*
         * Extensions Length
         */
        if (position + 2 > handshakeEnd) {
            return null;
        }

        int extensionsLength =
                readUnsignedShort(data, position);

        position += 2;

        int extensionsEnd =
                position + extensionsLength;

        if (extensionsEnd > handshakeEnd) {
            return null;
        }

        return findServerNameExtension(
                data,
                position,
                extensionsEnd
        );
    }

    private String findServerNameExtension(
            byte[] data,
            int position,
            int extensionsEnd) {

        while (position + 4 <= extensionsEnd) {

            int extensionType =
                    readUnsignedShort(data, position);

            position += 2;

            int extensionLength =
                    readUnsignedShort(data, position);

            position += 2;

            int extensionEnd =
                    position + extensionLength;

            if (extensionEnd > extensionsEnd) {
                return null;
            }

            if (extensionType == EXTENSION_SERVER_NAME) {

                return extractServerName(
                        data,
                        position,
                        extensionEnd
                );
            }

            position = extensionEnd;
        }

        return null;
    }

    private String extractServerName(
            byte[] data,
            int position,
            int extensionEnd) {

        /*
         * Server Name extension:
         *
         * 2 bytes Server Name List Length
         * 1 byte  Name Type
         * 2 bytes Name Length
         * N bytes Host Name
         */

        if (position + 2 > extensionEnd) {
            return null;
        }

        int serverNameListLength =
                readUnsignedShort(data, position);

        position += 2;

        int listEnd =
                position + serverNameListLength;

        if (listEnd > extensionEnd) {
            return null;
        }

        while (position + 3 <= listEnd) {

            int nameType =
                    data[position] & 0xFF;

            position++;

            int nameLength =
                    readUnsignedShort(data, position);

            position += 2;

            if (position + nameLength > listEnd) {
                return null;
            }

            /*
             * Name Type 0 = host_name
             */
            if (nameType == 0) {

                return new String(
                        data,
                        position,
                        nameLength,
                        StandardCharsets.US_ASCII
                );
            }

            position += nameLength;
        }

        return null;
    }

    private int readUnsignedShort(
            byte[] data,
            int offset) {

        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private int readUnsignedMedium(
            byte[] data,
            int offset) {

        return ((data[offset] & 0xFF) << 16)
                | ((data[offset + 1] & 0xFF) << 8)
                | (data[offset + 2] & 0xFF);
    }
}