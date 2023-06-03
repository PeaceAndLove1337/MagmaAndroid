package com.mpei.vkr.magmaencryption.domain.utils;

import java.nio.ByteBuffer;

public class TypeConverter {

    private TypeConverter() throws Exception {
        throw new Exception("Can't create instance of this util class");
    }

    public static int createNumberFromByteArray(byte[] inputByteArray){
        int result = 0;
        for (byte b : inputByteArray) {
            result = (result << 8) + (b & 0xFF);
        }
        return result;
    }

    public static byte[] createByteArrayFromInt(int inputNumber){
        byte[] bytes = new byte[Integer.BYTES];
        int length = bytes.length;
        for (int i = 0; i < length; i++) {
            bytes[length - i - 1] = (byte) (inputNumber & 0xFF);
            inputNumber >>= 8;
        }
        return bytes;
    }

    public static byte[] create64ByteArrayFromInt(int inputNumber) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(inputNumber);
        byte[] bytes = bb.array();
        byte[] res = new byte[64];
        System.arraycopy(bytes, 0, res, 64 - bytes.length, bytes.length);
        return res;
    }

    public long createLongFromByteArray(byte[] inputByteArray) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(inputByteArray);
        buffer.flip();//need flip
        return buffer.getLong();
    }

    public static byte[] createBytesFromLong(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }
}
