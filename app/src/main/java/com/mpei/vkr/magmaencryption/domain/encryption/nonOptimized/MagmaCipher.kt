import MagmaAdditionalFunctions.Functions.addTwoUByteArraysWithoutOverflow
import MagmaAdditionalFunctions.Functions.convertFromUByteArrayToUIntArray
import MagmaAdditionalFunctions.Functions.convertFromUIntToUByteArray
import MagmaAdditionalFunctions.Functions.convertHexToBin
import MagmaAdditionalFunctions.Functions.xorTwoUByteArrays

//32 бита = 4 байта, например 0xAF - 2 шестнадцатеричных разряда -> 1 байт
// -> 0xAFA123AD 8 шестнадцатеричных разрядов -> 4 байта

//Магма работает с 64-битными блоками
// 32 итерации
// Использует 256 битный ключ
class MagmaCipher {

    companion object Coding {

        //Sbox(от RFC 4357), используемый в раундовом преобразовании F
        private val sBox1: Array<Array<Byte>> = arrayOf(
            arrayOf(9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5),
            arrayOf(3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1),
            arrayOf(14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9),
            arrayOf(14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6),
            arrayOf(11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6),
            arrayOf(3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6),
            arrayOf(1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14),
            arrayOf(11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4),
        )

        //Sbox из ГОСТ-документа, используемый в раундовом преобразовании F
        private val sBox2: Array<Array<Byte>> = arrayOf(
            arrayOf(1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2),
            arrayOf(8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7),
            arrayOf(5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0),
            arrayOf(7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12),
            arrayOf(12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11),
            arrayOf(11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0),
            arrayOf(6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15),
            arrayOf(12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1),
        )

        //Функция раундового преобразования F
        //На вход подаётся один из подблоков длиной 32 бита, к нему XOR'ится итерационный ключ
        //Результат разбивается на 8 блоков по 4 бита и каждые 4 бита прогоняются через таблицу замен sBox
        //Результат замен циклически сдвигается влево на 11 бит
        fun fTransformation(transformableBytes: Array<UByte>, iterationKey: Array<UByte>): Array<UByte> {
            val resultOfSum = addTwoUByteArraysWithoutOverflow(transformableBytes, iterationKey)
            val resultOfReplacement = replacementTransformation(resultOfSum)
            return cyclicalSwigLeft(resultOfReplacement)
        }

        // Функция перестановок в соответствии с sBox'ом
        fun replacementTransformation(transformableBytes: Array<UByte>): Array<UByte> {
            val result = Array<UByte>(transformableBytes.size) { 0U }
            var arrayInBin = ""
            transformableBytes.forEach { arrayInBin += convertHexToBin(it) }
            val replacementElements = mutableListOf<String>()
            arrayInBin.chunked(4).forEachIndexed { index, elem ->
                replacementElements.add(sBox2[index][elem.toInt(2)].toString(16))
            }
            lateinit var newElem: String
            for (i in replacementElements.indices) {
                if (i % 2 == 0)
                    newElem = ""
                newElem += replacementElements[i]
                if (i % 2 != 0) {
                    result[i / 2] = newElem.toUByte(16)
                }
            }
            return result
        }

        //Процедура расширения ключей
        //Принимает на вход 256 бит возвращает 1024 бит т.е. 32 байта и возр 128 байт
        //Исходный ключ делится на последовательности по 4 байта (их получается 8 штук)
        //Далее эти 8 последовательностей циклически 3 раза впихиваются в результат и последний раз проход идёт в другую сторону
        //ПРИ ЭТОМ РАБОТА ИДЁТ ПО 4 байтам сразу!
        fun keyExpansion(inputKeys: Array<UInt>): Array<UInt> {
            val result = Array(inputKeys.size * 4) { 0U }
            val reversedKeys = inputKeys.reversed()
            var i = 0
            while (i != 24) {
                result[i] = inputKeys[i % 8]
                i++
            }
            while (i != 32) {
                result[i] = reversedKeys[i % 8]
                i++
            }
            return result
        }

        //Принимает на вход 64 бита(8 байт), возращает 64 бита(8 байт)
        fun encode(inputArray: Array<UByte>, roundKeys: Array<UInt>): Array<UByte> {
            var leftArray = inputArray.sliceArray(0..3)
            var rightArray = inputArray.sliceArray(4..7)

            for (i in 0..31) {
                val resultOfF_Transformation = fTransformation(rightArray, convertFromUIntToUByteArray(roundKeys[i]))
                val resultOfXOR = xorTwoUByteArrays(resultOfF_Transformation, leftArray)
                leftArray = rightArray
                rightArray = resultOfXOR
            }

            return rightArray.plus(leftArray)
        }

        //Принимает на вход 64 бита(8 байт), возращает 64 бита(8 байт)
        fun decode(inputArray: Array<UByte>, roundKeys: Array<UInt>): Array<UByte> {
            var leftArray = inputArray.sliceArray(0..3)
            var rightArray = inputArray.sliceArray(4..7)

            for (i in 31 downTo 0) {
                val resultOfF_Transformation = fTransformation(rightArray, convertFromUIntToUByteArray(roundKeys[i]))
                val resultOfXOR = xorTwoUByteArrays(resultOfF_Transformation, leftArray)
                leftArray = rightArray
                rightArray = resultOfXOR
            }

            return rightArray.plus(leftArray)
        }

        //Циклический сдвиг влево на 11 единиц разрядов
        fun cyclicalSwigLeft(inputArray: Array<UByte>): Array<UByte> {
            val result = Array<UByte>(inputArray.size) { 0U }
            val countOfOffset = 11
            var inputArrayInHexString = ""
            inputArray.forEach { inputArrayInHexString += convertHexToBin(it) }
            val swigablePart = inputArrayInHexString.substring(0, countOfOffset)
            val resultString = inputArrayInHexString.substring(countOfOffset) + swigablePart
            resultString.chunked(8).forEachIndexed { index, elem -> result[index] = elem.toUByte(2) }
            return result
        }

        //Процедура расширения входного массива байт до кратности 64
        fun blocksExpansion(inputArray: Array<UByte>): Array<UByte> {
            val mod8CountOfBytes = inputArray.size % 8
            return if (mod8CountOfBytes != 0) {
                val additionalArray = Array<UByte>(8 - mod8CountOfBytes) { 0U }
                inputArray.plus(additionalArray)
            } else inputArray
        }

        //Функции шифрования/расшифрования принимающие на вход любое кол-во байт и кодирующие блоки последовательно по 64 бита
        // Если имеется блок не кратный 64 битам, то он дополняется нулями до 64.
        fun inCodeBookEncode(inputArray: Array<UByte>, roundKeys: Array<UInt>): Array<UByte> {

            val expandedArray = blocksExpansion(inputArray)
            var result = Array<UByte>(0) { 0U }
            for (i in expandedArray.indices step 8) {
                result = result.plus(encode(expandedArray.sliceArray(i..i + 7), roundKeys))
                println("Iteration Block NUMER $i")
            }
            return result
        }

        //Функция расшифрования, бросающая эксепшн если входной массив не кратен 8 байтам
        //Если во входном массиве был паддинг в последнем блоке, то он удаляет его (паддинг в виде нулевых байт)
        fun inCodeBookDecode(inputArray: Array<UByte>, roundKeys: Array<UInt>): Array<UByte> {
            if (inputArray.size % 8 != 0)
                throw Exception("Входной массив не кратен 8 байтам, а значит не шифровался")
            var result = Array<UByte>(0) { 0U }

            for (i in inputArray.indices step 8) {
                result = result.plus(decode(inputArray.sliceArray(i..i + 7), roundKeys))
                println("Iteration Block NUMER $i")
            }


            return result.dropLastWhile { it == 0x00U.toUByte() }.toTypedArray()
        }

        fun mainMAGMAEncode(inputArray: Array<UByte>, initKey: ByteArray): Array<UByte> {
            val keyInUIntInSHA = convertFromUByteArrayToUIntArray(initKey.toUByteArray().toTypedArray())
            val roundKeys = keyExpansion(keyInUIntInSHA)
            return inCodeBookEncode(inputArray, roundKeys)
        }
        fun mainMAGMADecode(inputArray: Array<UByte>, initKey: ByteArray): Array<UByte> {
            val keyInUIntInSHA = convertFromUByteArrayToUIntArray(initKey.toUByteArray().toTypedArray())
            val roundKeys = keyExpansion(keyInUIntInSHA)
            return inCodeBookDecode(inputArray, roundKeys)
        }
    }
}

