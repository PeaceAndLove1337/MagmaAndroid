package com.mpei.vkr.magmaencryption.domain.encryption.optimized;



import com.mpei.vkr.magmaencryption.domain.utils.TypeConverter;
import com.mpei.vkr.magmaencryption.presentation.ProgressHelper;

import java.util.BitSet;

public class MagmaEncryptor {

    private final byte[] mExpandedKeys;

    /**
     * SBox в соответствии с RFC-4357
     */
    private static final byte[][] sBox1 = new byte[][]{
            {9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5},
            {3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1},
            {14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9},
            {14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6},
            {11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6},
            {3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6},
            {1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14},
            {11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4}
    };

    /**
     * SBox в соответствии с документацией, приведенной к ГОСТ
     */
    private static final byte[][] sBox2 = new byte[][]{
            {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
            {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
            {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
            {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
            {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
            {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
            {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
            {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1}
    };

    public MagmaEncryptor(byte[] encryptionKey) {
        mExpandedKeys = keyExpansion(encryptionKey);
    }

    public byte[] encryptInCodeBook(byte[] inputArray, ProgressHelper progressHelper) {
        int countOfFullBlocks = inputArray.length / 8;
        int residue = inputArray.length % 8;

        byte[] result = residue == 0 ? new byte[inputArray.length] : new byte[(countOfFullBlocks + 1) * 8];
        ;
        byte[] currentBlockToEncrypt = new byte[8];


        for (int i = 0; i < countOfFullBlocks; i++) {
            System.arraycopy(inputArray, i * 8, currentBlockToEncrypt, 0, 8);
            System.arraycopy(oneBlockEncode(currentBlockToEncrypt), 0, result, i * 8, 8);
            progressHelper.setProgressToBarInAnotherThread(
                    (int) Math.round(((double) i/ countOfFullBlocks) * 100)
            );
        }

        if (residue != 0) {
            currentBlockToEncrypt = new byte[8];
            System.arraycopy(inputArray, countOfFullBlocks*8, currentBlockToEncrypt, 0, residue);
            System.arraycopy(oneBlockEncode(currentBlockToEncrypt), 0, result, (countOfFullBlocks)*8, 8);
        }

        return result;
    }

    public byte[] decryptInCodeBook(byte[] inputArray, ProgressHelper progressHelper) {
        if (inputArray.length % 8!=0){
            throw new RuntimeException("INCORRECT INPUT ARRAY");
        }

        byte[] result = new byte[inputArray.length];
        ;
        byte[] currentBlockToDecrypt = new byte[8];

        for (int i = 0; i < inputArray.length / 8; i++) {
            System.arraycopy(inputArray, i * 8, currentBlockToDecrypt, 0, 8);
            System.arraycopy(oneBlockDecode(currentBlockToDecrypt), 0, result, i * 8, 8);
            progressHelper.setProgressToBarInAnotherThread(
                    (int) Math.round(((double) i/ ((double)inputArray.length / 8)) * 100)
            );
        }

        return result;
    }

    /**
     * Зашифровать один блок размерностью 64 бита (8 байт)
     *
     * @param blockToEncode кодируемый блок
     * @return результат шифрования
     */
    public byte[] oneBlockEncode(byte[] blockToEncode) {
        byte[] res = new byte[8];
        System.arraycopy(blockToEncode, 0, res, 0, 8);

        byte[] leftSubBlock = new byte[4];
        byte[] rightSubBlock = new byte[4];
        byte[] keyOnRound = new byte[4];

        for (int i = 0; i < 31; i++) {
            System.arraycopy(res, 0, leftSubBlock, 0, 4);
            System.arraycopy(res, 4, rightSubBlock, 0, 4);
            System.arraycopy(mExpandedKeys, i * 4, keyOnRound, 0, 4);
            System.arraycopy(rightSubBlock, 0, res, 0, 4);
            System.arraycopy(fTransformationFunWithXor(rightSubBlock, keyOnRound, leftSubBlock), 0, res, 4, 4);
        }

        System.arraycopy(res, 0, leftSubBlock, 0, 4);
        System.arraycopy(res, 4, rightSubBlock, 0, 4);
        System.arraycopy(mExpandedKeys, 124, keyOnRound, 0, 4);
        System.arraycopy(fTransformationFunWithXor(rightSubBlock, keyOnRound, leftSubBlock), 0, res, 0, 4);
        System.arraycopy(rightSubBlock, 0, res, 4, 4);
        return res;
    }

    /**
     * Расшифровать один блок размерностью 64 бита (8 байт)
     *
     * @param blockToDecode кодируемый блок
     * @return результат расшифрования
     */
    public byte[] oneBlockDecode(byte[] blockToDecode) {
        byte[] res = new byte[8];
        System.arraycopy(blockToDecode, 0, res, 0, 8);


        byte[] leftSubBlock = new byte[4];
        byte[] rightSubBlock = new byte[4];
        byte[] keyOnRound = new byte[4];

        for (int i = 0; i < 31; i++) {
            System.arraycopy(res, 0, leftSubBlock, 0, 4);
            System.arraycopy(res, 4, rightSubBlock, 0, 4);
            System.arraycopy(mExpandedKeys, (31 - i) * 4, keyOnRound, 0, 4);
            System.arraycopy(rightSubBlock, 0, res, 0, 4);
            System.arraycopy(fTransformationFunWithXor(rightSubBlock, keyOnRound, leftSubBlock), 0, res, 4, 4);
        }

        System.arraycopy(res, 0, leftSubBlock, 0, 4);
        System.arraycopy(res, 4, rightSubBlock, 0, 4);
        System.arraycopy(mExpandedKeys, 0, keyOnRound, 0, 4);
        System.arraycopy(fTransformationFunWithXor(rightSubBlock, keyOnRound, leftSubBlock), 0, res, 0, 4);
        System.arraycopy(rightSubBlock, 0, res, 4, 4);
        return res;
    }

    /**
     * Функция f-трансформации вместе с xor'ом дополнительного массива
     *
     * @param inputBytes массив входных байт для f-преобразования
     * @param key        ключ преобразования
     * @param leftArray  дополнительный массив для xor'a с ним результата f-трансформации
     * @return расширенный ключ
     */
    private byte[] fTransformationFunWithXor(byte[] inputBytes, byte[] key, byte[] leftArray) {
        return xorTwoByteArrays(fTransformationFun(inputBytes, key), leftArray);
    }

    /**
     * Функция f-трансформации
     *
     * @param inputBytes массив входных байт для f-преобразования
     * @param key        ключ преобразования
     * @return расширенный ключ
     */
    private byte[] fTransformationFun(byte[] inputBytes, byte[] key) {
        byte[] resultOfSum = sumWithoutOverflow(inputBytes, key);
        byte[] resultOfSubstitution = sBoxSubstitution(resultOfSum);
        int resultOfLeftShift = Integer.rotateLeft(TypeConverter.createNumberFromByteArray(resultOfSubstitution), 11);
        return TypeConverter.createByteArrayFromInt(resultOfLeftShift);
    }

    /**
     * Производит подстановку входного 4 байтного массива через sBox
     *
     * @param inputBytes массив входных байт длины 4
     * @return массив байт длины 4, прошедший через подстановку
     */
    private byte[] sBoxSubstitution(byte[] inputBytes) {
        if (inputBytes.length != 4) {
            throw new RuntimeException("sBox input byte array length not equals 4");
        }
        byte[] result = new byte[4];
        BitSet bitSet = BitSet.valueOf(inputBytes);
        int numOfRow = -1;
        for (int i = 0; i < 4; i++) {
            BitSet leftBitSet = bitSet.get(i * 8 + 4, (i * 8) + 8);
            BitSet rightBitSet = bitSet.get(i * 8, (i * 8) + 4);
            byte leftByte = leftBitSet.length() != 0 ? leftBitSet.toByteArray()[0] : 0;
            byte rightByte = rightBitSet.length() != 0 ? rightBitSet.toByteArray()[0] : 0;
            byte newLeftByte = sBox2[++numOfRow][leftByte];
            byte newRightByte = sBox2[++numOfRow][rightByte];

            BitSet resOf1 = BitSet.valueOf(new byte[]{newLeftByte}).get(0, 4);
            BitSet resOf2 = BitSet.valueOf(new byte[]{newRightByte}).get(0, 4);
            byte[] concRes = concatenateVectors(resOf2, resOf1).toByteArray();
            result[i] = concRes.length != 0 ? concRes[0] : 0;
        }
        return result;
    }

    /**
     * Функция конкатенации двух BitSet - наборов
     *
     * @param firstInputVector  массив, к которому производится конкатенация
     * @param secondInputVector конкатенирующийся массив
     * @return результат конкатенации
     */
    private BitSet concatenateVectors(BitSet firstInputVector, BitSet secondInputVector) {
        BitSet clonedFirstVector = (BitSet) firstInputVector.clone();
        BitSet clonedSecondVector = (BitSet) secondInputVector.clone();
        int n = 4;
        int index = -1;
        while (index < (clonedSecondVector.length() - 1)) {
            index = clonedSecondVector.nextSetBit((index + 1));
            clonedFirstVector.set((index + n));
        }
        return clonedFirstVector;
    }

    /**
     * Производит расширение ключей на основе внутреннего поля mEncryptionKey,
     * которое задается при инициализации инстанса класса
     *
     * @return расширенный ключ
     */
    private byte[] keyExpansion(byte[] mEncryptionKey) {
        byte[] result = new byte[mEncryptionKey.length * 4];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(mEncryptionKey, 0, result, mEncryptionKey.length * i, mEncryptionKey.length);
        }

        byte[] reversedEncryptionKey = new byte[mEncryptionKey.length];
        int j = 0;

        for (int i = mEncryptionKey.length - 4; i >= 0; i -= 4) {
            System.arraycopy(mEncryptionKey, i, reversedEncryptionKey, j, 4);
            j += 4;
        }

        System.arraycopy(reversedEncryptionKey, 0, result, mEncryptionKey.length * 3, mEncryptionKey.length);
        return result;
    }

    /**
     * Сложить два байтовых массива в виде int' представлений без переполнения (т.е. по модулю 2^32)
     *
     * @param firstArray  первый массив
     * @param secondArray второй массив
     * @return результат суммы
     */
    private byte[] sumWithoutOverflow(byte[] firstArray, byte[] secondArray) {
        int firstNumber = TypeConverter.createNumberFromByteArray(firstArray);
        int secondNumber = TypeConverter.createNumberFromByteArray(secondArray);
        return TypeConverter.createByteArrayFromInt(firstNumber + secondNumber);
    }

    /**
     * Сложение по модулю 2 двух байтовых массивов одинаковой длины
     *
     * @param firstArray  первый массив
     * @param secondArray второй массив
     * @return результат xor'a
     */
    private byte[] xorTwoByteArrays(byte[] firstArray, byte[] secondArray) {
        byte[] result = new byte[firstArray.length];
        for (int i = 0; i < firstArray.length; i++) {
            result[i] = (byte) (firstArray[i] ^ secondArray[i]);
        }
        return result;
    }

}
