package com.mpei.vkr.magmaencryption.presentation.viewmodels

import android.os.Build
import androidx.annotation.RequiresApi
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.mpei.vkr.magmaencryption.domain.encryption.MagmaParallelEncryptor
import com.mpei.vkr.magmaencryption.presentation.ProgressHelper
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class MainViewModel : ViewModel() {

    private val stateOfEncryption = MutableLiveData<ByteArray>()
    private val stateOfDecryption = MutableLiveData<ByteArray>()

    @RequiresApi(Build.VERSION_CODES.N)
    fun makeEncodingInThread(
        encodeKeyOnPassword: String,
        byteArrayToEncode: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val encodeKeyInBytes = MessageDigest.getInstance("SHA-256")
                .digest(encodeKeyOnPassword.toByteArray(StandardCharsets.UTF_8))
            val encryptor = MagmaParallelEncryptor(encodeKeyInBytes, 14)
            stateOfEncryption.postValue(encryptor.encryptInCodeBook(byteArrayToEncode, progressHelper))
        }.start()
    }

    fun makeDecodingInThread(
        decodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val encodeKeyInBytes = MessageDigest.getInstance("SHA-256")
                .digest(decodeKeyOnPassword.toByteArray(StandardCharsets.UTF_8))
            val encryptor = MagmaParallelEncryptor(encodeKeyInBytes, 14)
            stateOfDecryption.postValue(encryptor.decryptInCodeBook(byteArrayOfSelectedFile, progressHelper))
        }.start()
    }

    fun getEncryptionState(): LiveData<ByteArray> = stateOfEncryption
    fun getDecryptionState(): LiveData<ByteArray> = stateOfDecryption
}