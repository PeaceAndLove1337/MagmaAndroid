package com.mpei.vkr.magmaencryption.domain.utils;

public class ArrayHelper {

    private ArrayHelper() throws Exception {
        throw new Exception("Can't create instance of this util class");
    }

    public static byte[] reverseArray(byte[] inputArray) {
        byte[] newArray = new byte[inputArray.length];

        for (int i = 0; i < inputArray.length; i++) {
            newArray[inputArray.length - 1 - i] = inputArray[i];
        }

        return newArray;
    }

    public static byte[] expandByteArrayTo64Bits(byte[] inputArray) {
        if (inputArray.length != 8) {
            byte[] result = new byte[8];
            System.arraycopy(inputArray, 0, result, 0, inputArray.length);
            return result;
        } else {
            return inputArray;
        }
    }
}
