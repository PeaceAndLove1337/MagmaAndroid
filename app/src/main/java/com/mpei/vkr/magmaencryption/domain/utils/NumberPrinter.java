package com.mpei.vkr.magmaencryption.domain.utils;

import java.util.Arrays;

public class NumberPrinter {

    private NumberPrinter() throws Exception {
        throw new Exception("Can't create instance of this util class");
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static void PrintByteArray(byte[] inputArray) {
        System.out.println(Arrays.toString(inputArray));
    }

    public static void PrintUbyteArray(byte[] inputArray) {
        int[] resultArray = new int[inputArray.length];
        for (int i = 0; i < inputArray.length; i++) {
            resultArray[i] = Byte.toUnsignedInt(inputArray[i]);
        }
        System.out.println(Arrays.toString(resultArray));
    }

    public static void PrintHexArray(byte[] inputArray) {
        char[] hexChars = new char[inputArray.length * 2];
        for (int j = 0; j < inputArray.length; j++) {
            int v = inputArray[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        for (int i = 0; i < hexChars.length; i++) {
            if (i % 2 != 0) {
                System.out.print(hexChars[i] + " ");
            } else {
                System.out.print(hexChars[i]);
            }
        }
        System.out.println();
    }

    public static void printByteInBinary(byte input){
        System.out.println(String.format("%8s", Integer.toBinaryString(input & 0xFF)).replace(' ', '0'));
    }

}
