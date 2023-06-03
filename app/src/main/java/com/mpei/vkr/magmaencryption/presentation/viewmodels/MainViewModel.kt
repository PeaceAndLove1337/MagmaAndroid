package com.mpei.vkr.magmaencryption.presentation.viewmodels

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import com.mpei.vkr.magmaencryption.R
import com.mpei.vkr.magmaencryption.data.MyTrustManager
import com.mpei.vkr.magmaencryption.domain.encryption.PasswordToKeyConverter
import com.mpei.vkr.magmaencryption.domain.encryption.nonOptimized.mainAndroidMAGMADecode
import com.mpei.vkr.magmaencryption.domain.encryption.nonOptimized.mainAndroidMAGMAEncode
import com.mpei.vkr.magmaencryption.domain.encryption.optimized.MagmaEncryptor
import com.mpei.vkr.magmaencryption.domain.encryption.optimized.MagmaParallelEncryptor
import com.mpei.vkr.magmaencryption.presentation.ProgressHelper
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.InputStream
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class MainViewModel : ViewModel() {

    private val stateOfEncryption = MutableLiveData<ByteArray>()
    private val stateOfDecryption = MutableLiveData<ByteArray>()

    @ExperimentalUnsignedTypes
    fun makeNonOptimizedEncoding(
        encodeKeyOnPassword: String,
        byteArrayToEncode: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val encodeKeyInBytes = PasswordToKeyConverter(encodeKeyOnPassword).bytesFromPassByStreebog
            val result = mainAndroidMAGMAEncode(
                byteArrayToEncode.toUByteArray().toTypedArray(),
                encodeKeyInBytes,
                progressHelper
            )
            stateOfEncryption.postValue(result.toUByteArray().toByteArray())
        }.start()
    }

    @ExperimentalUnsignedTypes
    fun makeNonOptimizedDecoding(
        decodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val decodeKeyInBytes = PasswordToKeyConverter(decodeKeyOnPassword).bytesFromPassByStreebog
            val result = mainAndroidMAGMADecode(
                byteArrayOfSelectedFile.toUByteArray().toTypedArray(),
                decodeKeyInBytes,
                progressHelper
            )
            stateOfDecryption.postValue(result.toUByteArray().toByteArray())
        }.start()
    }

    fun makeOptimizedEncoding(
        encodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val encodeKeyInBytes = PasswordToKeyConverter(encodeKeyOnPassword).bytesFromPassByStreebog
            val encryptor = MagmaEncryptor(
                encodeKeyInBytes
            )
            stateOfEncryption.postValue(encryptor.encryptInCodeBook(byteArrayOfSelectedFile, progressHelper))
        }.start()
    }

    fun makeOptimizedDecoding(
        decodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val decodeKeyInBytes = PasswordToKeyConverter(decodeKeyOnPassword).bytesFromPassByStreebog
            val encryptor = MagmaEncryptor(
                decodeKeyInBytes
            )
            stateOfDecryption.postValue(encryptor.decryptInCodeBook(byteArrayOfSelectedFile, progressHelper))
        }.start()
    }

    fun makeOptimizedParallelEncoding(
        encodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val encodeKeyInBytes = PasswordToKeyConverter(encodeKeyOnPassword).bytesFromPassByStreebog
            val encryptor = MagmaParallelEncryptor(
                encodeKeyInBytes
            )
            stateOfEncryption.postValue(encryptor.encryptInCodeBook(byteArrayOfSelectedFile, progressHelper))
        }.start()
    }

    fun makeOptimizedParallelDecoding(
        decodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray,
        progressHelper: ProgressHelper
    ) {
        Thread {
            val decodeKeyInBytes = PasswordToKeyConverter(decodeKeyOnPassword).bytesFromPassByStreebog
            val encryptor = MagmaParallelEncryptor(
                decodeKeyInBytes
            )
            stateOfDecryption.postValue(encryptor.decryptInCodeBook(byteArrayOfSelectedFile, progressHelper))
        }.start()
    }

    fun makeBackEncoding(
        encodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray
    ) {
        Thread {
            val client = OkHttpClient.Builder()
                .callTimeout(600, TimeUnit.SECONDS)
                .readTimeout(600, TimeUnit.SECONDS)
                .writeTimeout(600, TimeUnit.SECONDS)
                .build()
            try {
                val body = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart(
                        "file", "file_name",
                        byteArrayOfSelectedFile.toRequestBody(
                            MULTIPART_FORM_DATA_PART.toMediaTypeOrNull()
                        )
                    )
                    .addFormDataPart(PASSWORD_FORM_DATA_PART, encodeKeyOnPassword)
                    .build()
                val request = Request.Builder()
                    .url(MAGMA_DEFAULT_ENCODE)
                    .post(body)
                    .build()
                val response = client.newCall(request).execute()
                val res = response.body?.bytes()
                stateOfEncryption.postValue(res)
            } catch (e: Exception) {
                println("makeBackEncoding ERROR CONNECTING TO")
                stateOfEncryption.postValue(null)
            }
        }.start()
    }

    fun makeBackDecoding(
        decodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray
    ) {
        Thread {
            val client = OkHttpClient.Builder()
                .callTimeout(600, TimeUnit.SECONDS)
                .readTimeout(600, TimeUnit.SECONDS)
                .writeTimeout(600, TimeUnit.SECONDS)
                .build()
            try {
                val body = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart(
                        "file", "file_name",
                        byteArrayOfSelectedFile.toRequestBody(
                            MULTIPART_FORM_DATA_PART.toMediaTypeOrNull()
                        )
                    )
                    .addFormDataPart(PASSWORD_FORM_DATA_PART, decodeKeyOnPassword)
                    .build()
                val request = Request.Builder()
                    .url(MAGMA_DEFAULT_DECODE)
                    .post(body)
                    .build()

                val response = client.newCall(request).execute()
                val res = response.body?.bytes()
                stateOfDecryption.postValue(res)
            } catch (e: Exception) {
                println("makeBackDecoding ERROR CONNECTING TO")
                stateOfDecryption.postValue(null)
            }
        }.start()
    }

    fun makeBackSslEncoding(
        context: Context,
        encodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray
    ) {
        Thread {
            val keyStore = KeyStore.getInstance("BKS")
            val inputStream: InputStream = context.resources.openRawResource(R.raw.keystore)
            keyStore.load(inputStream, KEY_STORE_PASSWORD.toCharArray())
            val trustManager = MyTrustManager(keyStore)
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(trustManager), SecureRandom())
            val client: OkHttpClient = OkHttpClient.Builder()
                .sslSocketFactory(sslContext.socketFactory, trustManager as X509TrustManager)
                .callTimeout(600, TimeUnit.SECONDS)
                .readTimeout(600, TimeUnit.SECONDS)
                .writeTimeout(600, TimeUnit.SECONDS)
                .hostnameVerifier { _, _ -> true }
                .build()
            try {
                val body = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart(
                        "file", "file_name",
                        byteArrayOfSelectedFile.toRequestBody(
                            MULTIPART_FORM_DATA_PART.toMediaTypeOrNull()
                        )
                    )
                    .addFormDataPart(PASSWORD_FORM_DATA_PART, encodeKeyOnPassword)
                    .build()
                val request = Request.Builder()
                    .url(MAGMA_DEFAULT_SSL_ENCODE)
                    .post(body)
                    .build()
                val response = client.newCall(request).execute()
                val res = response.body?.bytes()
                stateOfEncryption.postValue(res)
            } catch (e: Exception) {
                println("makeBackSslEncoding ERROR CONNECTING TO")
                stateOfEncryption.postValue(null)
            }
        }.start()
    }

    fun makeBackSslDecoding(
        context: Context,
        decodeKeyOnPassword: String,
        byteArrayOfSelectedFile: ByteArray
    ) {
        Thread {
            val keyStore = KeyStore.getInstance("BKS")
            val inputStream: InputStream = context.resources.openRawResource(R.raw.keystore)
            keyStore.load(inputStream, KEY_STORE_PASSWORD.toCharArray())
            val trustManager = MyTrustManager(keyStore)
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(trustManager), SecureRandom())
            val client: OkHttpClient = OkHttpClient.Builder()
                .sslSocketFactory(sslContext.socketFactory, trustManager as X509TrustManager)
                .callTimeout(600, TimeUnit.SECONDS)
                .readTimeout(600, TimeUnit.SECONDS)
                .writeTimeout(600, TimeUnit.SECONDS)
                .hostnameVerifier { _, _ -> true }
                .build()
            try {
                val body = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart(
                        "file", "file_name",
                        byteArrayOfSelectedFile.toRequestBody(
                            MULTIPART_FORM_DATA_PART.toMediaTypeOrNull()
                        )
                    )
                    .addFormDataPart(PASSWORD_FORM_DATA_PART, decodeKeyOnPassword)
                    .build()
                val request = Request.Builder()
                    .url(MAGMA_DEFAULT_SSL_DECODE)
                    .post(body)
                    .build()

                val response = client.newCall(request).execute()
                val res = response.body?.bytes()
                stateOfDecryption.postValue(res)
            } catch (e: Exception) {
                println("makeBackSslDecoding ERROR CONNECTING TO")
                stateOfDecryption.postValue(null)
            }
        }.start()
    }

    fun getEncryptionState(): LiveData<ByteArray> = stateOfEncryption
    fun getDecryptionState(): LiveData<ByteArray> = stateOfDecryption

    private companion object {
        const val LOCAL_ADDRESS_URL_NO_SSL = "http://192.168.1.125:8082/"
        const val LOCAL_ADDRESS_URL_SSL = "https://192.168.1.125:8443/"
        const val MAGMA_ENCODE_ROUTE = "magma/encode"
        const val MAGMA_DECODE_ROUTE = "magma/decode"
        const val MAGMA_DEFAULT_ENCODE =
            "$LOCAL_ADDRESS_URL_NO_SSL$MAGMA_ENCODE_ROUTE?mode=default&threads=multi-threaded"
        const val MAGMA_DEFAULT_DECODE =
            "$LOCAL_ADDRESS_URL_NO_SSL$MAGMA_DECODE_ROUTE?mode=default&threads=multi-threaded"
        const val MAGMA_DEFAULT_SSL_ENCODE =
            "$LOCAL_ADDRESS_URL_SSL$MAGMA_ENCODE_ROUTE?mode=default&threads=multi-threaded"
        const val MAGMA_DEFAULT_SSL_DECODE =
            "$LOCAL_ADDRESS_URL_SSL$MAGMA_DECODE_ROUTE?mode=default&threads=multi-threaded"

        const val PASSWORD_FORM_DATA_PART = "password"
        const val MULTIPART_FORM_DATA_PART = "multipart/form-data"
        const val KEY_STORE_PASSWORD = "passwordKeyStore123456"
    }
}