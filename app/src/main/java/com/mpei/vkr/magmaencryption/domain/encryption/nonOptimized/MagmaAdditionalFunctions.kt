import java.security.MessageDigest

class MagmaAdditionalFunctions {

    companion object Functions {

        /*fun takeInitKeyFromString(inputString: String): Array<UByte> {
            val inputBytes = inputString.toByteArray().toUByteArray().toTypedArray()
            return getHash256(inputBytes)
        }*/

        fun takeInitKeyFromStringSHA256(inputString: String): Array<UByte> {
            val inputBytes = inputString.toByteArray()
            val digest = MessageDigest.getInstance("SHA-256")
            return digest.digest(inputBytes).toUByteArray().toTypedArray()
        }

        //Функция XOR'a двух массивов
        fun xorTwoUByteArrays(firstArray: Array<UByte>, secondArray: Array<UByte>): Array<UByte> {
            val result: Array<UByte> = Array(firstArray.size) { 0U }
            for (i in firstArray.indices)
                result[i] = firstArray[i] xor secondArray[i]
            return result
        }


        fun convertFromUByteArrayToUInt(inputUInt: Array<UByte>): UInt {
            var result = ""
            inputUInt.forEach {
                var inString = it.toString(16)
                while (inString.length != 2) {
                    inString = "0$inString"
                }
                result += inString
            }
            return result.toUInt(16)
        }

        //Сложение по модулю 2^32-1
        fun addTwoUByteArraysWithoutOverflow(firstArray: Array<UByte>, secondArray: Array<UByte>): Array<UByte> {
            var firstArrayInString = ""
            var secondArrayInString = ""
            for (i in firstArray.indices) {
                firstArrayInString += convertHexToStringWithoutLosingZeros(firstArray[i])
                secondArrayInString += convertHexToStringWithoutLosingZeros(secondArray[i])
            }
            var sumInString = (firstArrayInString.toUInt(16) + secondArrayInString.toUInt(16)).toString(16)
            while (sumInString.length!=8)
                sumInString="0$sumInString"
            return sumInString.chunked(2).map { it.toUByte(16) }.toTypedArray()
        }


        //Используется при конвертации ключей
        fun convertFromUByteArrayToUIntArray(uByteArray: Array<UByte>):Array<UInt>{
            var result =Array<UInt>(0){0U}
            for (i in uByteArray.indices step 4){
                val currentBlock = uByteArray.sliceArray(i..i+3)
                result=result.plus(convertFromUByteArrayToUInt(currentBlock))
            }
            return result
        }

        //Конвертация из UInt в Array<UByte>
        fun convertFromUIntToUByteArray(inputUInt: UInt): Array<UByte> {
            var inString=inputUInt.toString(16)
            while (inString.length!=8){
                inString="0$inString"
            }
            val result = inString.chunked(2).map { it.toUByte(16) }.toTypedArray()
            return result
        }

        //Конвертация из 16 системы в двоичную без потери нулей вначале
        fun convertHexToBin(inputUByte: UByte): String {
            var result = inputUByte.toString(2)
            while (result.length != 8) {
                result = "0$result"
            }
            return result
        }

        fun convertHexToStringWithoutLosingZeros(inputUByte: UByte): String {
            var result = inputUByte.toString(16)
            while (result.length != 2) {
                result = "0$result"
            }
            return result
        }

    }
}