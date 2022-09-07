package com.mpei.vkr.magmaencryption.domain.utils;

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
}
