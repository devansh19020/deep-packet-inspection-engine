package com.devansh.dpi.application;

import com.devansh.dpi.enums.TlsContentType;
import com.devansh.dpi.model.TlsInfo;

public class TLSParser {

    private static final int TLS_HEADER_LENGTH = 5;

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
                ((payload[3] & 0xFF) << 8)
                        | (payload[4] & 0xFF);

        return new TlsInfo(
                contentType,
                majorVersion,
                minorVersion,
                recordLength
        );
    }
}
