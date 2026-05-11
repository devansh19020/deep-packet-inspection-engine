package com.devansh.dpi.util;


public final class ByteUtils {

    private ByteUtils() {}

    public static String readMac(
            byte[] data,
            int offset) {

        StringBuilder builder =
                new StringBuilder();

        for(int i=0;i<6;i++){

            builder.append(

                    String.format("%02X",
                            data[offset+i] & 0xFF)

            );

            if(i!=5)
                builder.append(":");
        }

        return builder.toString();
    }

    public static int readUnsignedShort(
            byte[] data,
            int offset){

        return ((data[offset] & 0xFF) << 8)

                |

                (data[offset+1] & 0xFF);

    }

    public static String readIPv4(
            byte[] data,
            int offset){

        return (data[offset] & 0xFF) + "." +
                (data[offset+1] & 0xFF) + "." +
                (data[offset+2] & 0xFF) + "." +
                (data[offset+3] & 0xFF);

    }

    public static long readUnsignedInt(
            byte[] data,
            int offset){

        return ((long)(data[offset] & 0xFF) << 24)
                |
                ((long)(data[offset+1] & 0xFF) << 16)
                |
                ((long)(data[offset+2] & 0xFF) << 8)
                |
                (long)(data[offset+3] & 0xFF);

    }

}