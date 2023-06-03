package com.mpei.vkr.magmaencryption.domain.encryption.nonOptimized

import MagmaAdditionalFunctions.Functions.convertFromUByteArrayToUIntArray

import MagmaCipher.Coding.blocksExpansion
import MagmaCipher.Coding.decode
import MagmaCipher.Coding.encode
import MagmaCipher.Coding.keyExpansion
import com.mpei.vkr.magmaencryption.presentation.ProgressHelper

//Функции шифрования/расшифрования принимающие на вход любое кол-во байт и кодирующие блоки последовательно по 64 бита
// Если имеется блок не кратный 64 битам, то он дополняется нулями до 64.
fun inCodeBookEncode(
    inputArray: Array<UByte>, roundKeys: Array<UInt>,
    progressHelper: ProgressHelper
): Array<UByte> {
    val expandedArray = blocksExpansion(inputArray)
    var result = Array<UByte>(0) { 0U }
    val currentCountOfProgress = expandedArray.size
    var progress = 0.0
    for (i in expandedArray.indices step 8) {
        result = result.plus(encode(expandedArray.sliceArray(i..i + 7), roundKeys))
        progress = (i.toDouble() / currentCountOfProgress) * 100
        progressHelper.setProgressToBarInAnotherThread(progress.toInt())
    }
    return result
}

//Функция расшифрования, бросающая эксепшн если входной массив не кратен 8 байтам
//Если во входном массиве был паддинг в последнем блоке, то он удаляет его (паддинг в виде нулевых байт)
fun inCodeBookDecode(
    inputArray: Array<UByte>,
    roundKeys: Array<UInt>,
    progressHelper: ProgressHelper
): Array<UByte> {
    if (inputArray.size % 8 != 0)
        throw Exception("Входной массив не кратен 8 байтам, а значит не шифровался")
    var result = Array<UByte>(0) { 0U }

    val currentCountOfProgress = inputArray.size
    var progress = 0.0

    for (i in inputArray.indices step 8) {
        result = result.plus(decode(inputArray.sliceArray(i..i + 7), roundKeys))
        progress = (i.toDouble() / currentCountOfProgress) * 100
        progressHelper.setProgressToBarInAnotherThread(progress.toInt())
    }

    return result.dropLastWhile { it == 0x00U.toUByte() }.toTypedArray()
}

fun mainAndroidMAGMAEncode(
    inputArray: Array<UByte>,
    initKey: ByteArray,
    progressHelper: ProgressHelper
): Array<UByte> {

    val keyInUIntInStreebog = convertFromUByteArrayToUIntArray(initKey.toUByteArray().toTypedArray())
    val roundKeys = keyExpansion(keyInUIntInStreebog)
    return inCodeBookEncode(inputArray, roundKeys, progressHelper)
}

fun mainAndroidMAGMADecode(
    inputArray: Array<UByte>,
    initKey: ByteArray,
    progressHelper: ProgressHelper
): Array<UByte> {
    val keyInUIntInStreebog = convertFromUByteArrayToUIntArray(initKey.toUByteArray().toTypedArray())
    val roundKeys = keyExpansion(keyInUIntInStreebog)

    return inCodeBookDecode(inputArray, roundKeys, progressHelper)
}
