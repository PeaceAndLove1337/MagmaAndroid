package com.mpei.vkr.magmaencryption.presentation.views

import android.Manifest
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.provider.OpenableColumns
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.RadioButton
import android.widget.TextView
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.lifecycle.ViewModelProvider
import com.mpei.vkr.magmaencryption.MagmaApplication
import com.mpei.vkr.magmaencryption.R
import com.mpei.vkr.magmaencryption.presentation.ProgressHelper
import com.mpei.vkr.magmaencryption.presentation.viewmodels.MainViewModel
import java.io.File
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var explorerButton: Button
    private lateinit var encodeButton: Button
    private lateinit var decodeButton: Button
    private lateinit var editTextPasswordKey: EditText
    private lateinit var editTextFileName: EditText
    private lateinit var textViewNameOfCurrentFile: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var waitBar: ProgressBar

    private lateinit var radioButtonNonOptimized: RadioButton
    private lateinit var radioButtonOptimized: RadioButton
    private lateinit var radioButtonOptimizedParallelized: RadioButton
    private lateinit var radioButtonOnBack: RadioButton
    private lateinit var radioButtonOnBackWithSsl: RadioButton

    private lateinit var byteArrayOfSelectedFile: ByteArray

    private lateinit var mainViewModel: MainViewModel

    @RequiresApi(Build.VERSION_CODES.N)
    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(R.style.Theme_MagmaEncryption)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViews()
        initButtons()
        initViewModel()
        initObservers()
        requestPermissions()
    }

    private fun findViews() {
        explorerButton = findViewById(R.id.button_explorer)
        encodeButton = findViewById(R.id.buttonEncode)
        decodeButton = findViewById(R.id.buttonDecode)
        editTextPasswordKey = findViewById(R.id.editTextPasswordKey)
        editTextFileName = findViewById(R.id.editTextFileName)
        textViewNameOfCurrentFile = findViewById(R.id.current_file_text_view)
        progressBar = findViewById(R.id.progressBar)
        radioButtonNonOptimized = findViewById(R.id.radioButtonNonOptimizedRealization)
        radioButtonOptimized = findViewById(R.id.radioButtonOptimizedRealization)
        radioButtonOptimizedParallelized = findViewById(R.id.radioButtonParallelizedOptimized)
        radioButtonOnBack = findViewById(R.id.radioButtonBackendOptimizedRealization)
        radioButtonOnBackWithSsl = findViewById(R.id.radioButtonBackendOptimizedWithSsl)
        waitBar = findViewById(R.id.wait_bar)
    }

    private fun initViewModel() {
        mainViewModel = ViewModelProvider(this).get(MainViewModel::class.java)
    }

    private fun initObservers() {
        mainViewModel.getEncryptionState().observe(this) {
            try {
                if (it == null) {
                    throw java.lang.Exception()
                }
                createFile(
                    it,
                    MagmaApplication.takeApplicationEncodedFilesPath(),
                    "/${editTextFileName.text}"
                )
                makeToastSuccessEncoded()
                makeElementsEnabled(true)
                waitBar.visibility = View.GONE
                progressBar.progress = 0
            } catch (ex: Exception) {
                waitBar.visibility = View.GONE
                progressBar.progress = 0
                makeElementsEnabled(true)
                makeToastError()
                Log.e("MAIN_ACTIVITY_ENCRYPTION_STATE_EXCEPCTION", ex.toString())
            }
        }
        mainViewModel.getDecryptionState().observe(this) {
            try {
                if (it == null) {
                    throw java.lang.Exception()
                }
                createFile(
                    it,
                    MagmaApplication.takeApplicationDecodedFilesPath(),
                    "/${editTextFileName.text}"
                )
                makeToastSuccessDecoded()
                makeElementsEnabled(true)
                waitBar.visibility = View.GONE
                progressBar.progress = 0
            } catch (ex: Exception) {
                waitBar.visibility = View.GONE
                progressBar.progress = 0
                makeElementsEnabled(true)
                makeToastError()
                Log.e("MAIN_ACTIVITY_DECRYPTION_STATE_EXCEPCTION", ex.toString())
            }
        }
    }

    private fun createProgressHelper() =
        ProgressHelper(progressBar, Handler())

    @RequiresApi(Build.VERSION_CODES.N)
    private fun initButtons() {
        explorerButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.type = "*/*"
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            startActivityForResult(Intent.createChooser(intent, "Select a file to Encode"), FILE_SELECT_CODE)
        }
        encodeButton.setOnClickListener {
            val encodeKeyOnPassword = editTextPasswordKey.text.toString()
            val fileNameText = editTextFileName.text.toString()
            when {
                encodeKeyOnPassword.isEmpty() -> makeToastIsEmptyPasswordKey()
                fileNameText.isEmpty() -> makeToastIsEmptyFileName()
                else -> when {
                    !checkPasswordGoodLength(encodeKeyOnPassword) -> makeToastBadPasswordLength()
                    !checkPasswordIsEasy(encodeKeyOnPassword) -> makeToastBadPasswordEasy()
                    else -> {
                        waitBar.visibility = View.VISIBLE
                        makeElementsEnabled(false)
                        when {
                            radioButtonNonOptimized.isChecked -> mainViewModel.makeNonOptimizedEncoding(
                                encodeKeyOnPassword,
                                byteArrayOfSelectedFile,
                                createProgressHelper()
                            )
                            radioButtonOptimized.isChecked -> mainViewModel.makeOptimizedEncoding(
                                encodeKeyOnPassword,
                                byteArrayOfSelectedFile,
                                createProgressHelper()
                            )
                            radioButtonOptimizedParallelized.isChecked -> mainViewModel.makeOptimizedParallelEncoding(
                                encodeKeyOnPassword,
                                byteArrayOfSelectedFile,
                                createProgressHelper()
                            )
                            radioButtonOnBack.isChecked -> mainViewModel.makeBackEncoding(
                                encodeKeyOnPassword,
                                byteArrayOfSelectedFile
                            )
                            radioButtonOnBackWithSsl.isChecked -> mainViewModel.makeBackSslEncoding(
                                baseContext,
                                encodeKeyOnPassword,
                                byteArrayOfSelectedFile
                            )
                            else -> {
                                makeElementsEnabled(true)
                                makeToastNotSelectedRealization()
                            }
                        }
                    }
                }
            }
        }
        decodeButton.setOnClickListener {
            val decodeKeyOnPassword = editTextPasswordKey.text.toString()
            val fileNameText = editTextFileName.text.toString()
            when {
                decodeKeyOnPassword.isEmpty() -> makeToastIsEmptyPasswordKey()
                fileNameText.isEmpty() -> makeToastIsEmptyFileName()
                else -> {
                    when {
                        !checkPasswordGoodLength(decodeKeyOnPassword) -> makeToastBadPasswordLength()
                        !checkPasswordIsEasy(decodeKeyOnPassword) -> makeToastBadPasswordEasy()
                        else -> {
                            makeElementsEnabled(false)
                            waitBar.visibility = View.VISIBLE
                            when {
                                radioButtonNonOptimized.isChecked -> mainViewModel.makeNonOptimizedDecoding(
                                    decodeKeyOnPassword,
                                    byteArrayOfSelectedFile,
                                    createProgressHelper()
                                )
                                radioButtonOptimized.isChecked -> mainViewModel.makeOptimizedDecoding(
                                    decodeKeyOnPassword,
                                    byteArrayOfSelectedFile,
                                    createProgressHelper()
                                )
                                radioButtonOptimizedParallelized.isChecked -> mainViewModel.makeOptimizedParallelDecoding(
                                    decodeKeyOnPassword,
                                    byteArrayOfSelectedFile,
                                    createProgressHelper()
                                )
                                radioButtonOnBack.isChecked -> mainViewModel.makeBackDecoding(
                                    decodeKeyOnPassword,
                                    byteArrayOfSelectedFile
                                )
                                radioButtonOnBackWithSsl.isChecked -> mainViewModel.makeBackSslDecoding(
                                    baseContext,
                                    decodeKeyOnPassword,
                                    byteArrayOfSelectedFile
                                )
                                else -> {
                                    makeElementsEnabled(true)
                                    makeToastNotSelectedRealization()
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == FILE_SELECT_CODE) {
            if (resultCode == RESULT_OK) {
                Log.i("FILE READING:", "File was correctly read")
                val uri: Uri = data?.data!!
                byteArrayOfSelectedFile = readBytes(this, uri)!!
                encodeButton.isEnabled = true
                decodeButton.isEnabled = true
                textViewNameOfCurrentFile.text = ""
                textViewNameOfCurrentFile.text = getFileName(uri)
            } else {
                Log.e("FILE READING:", "Failed to read file")
            }
        }
    }

    private fun makeElementsEnabled(isEnabled: Boolean) {
        encodeButton.isEnabled = isEnabled
        decodeButton.isEnabled = isEnabled
        explorerButton.isEnabled = isEnabled
        editTextPasswordKey.isEnabled = isEnabled
        editTextFileName.isEnabled = isEnabled
        radioButtonOnBackWithSsl.isEnabled = isEnabled
        radioButtonOnBack.isEnabled = isEnabled
        radioButtonOptimized.isEnabled = isEnabled
        radioButtonOptimizedParallelized.isEnabled = isEnabled
        radioButtonNonOptimized.isEnabled = isEnabled
    }

    private fun checkPasswordIsEasy(inputString: String): Boolean {
        val badPasswords = arrayListOf(
            "123456", "123456789", "qwerty", "12345678", "111111", "1234567890", "1234567", "password", "123123",
            "987654321", "qweryuiop", "mynoob", "123321", "666666", "atcskd2w", "7777777", "1q2w3e4r", "654321",
            "555555", "3rjs1la7qe", "google", "1q2w3e4r5t", "123qwe", "zxcvbnm", "1q2w3e",
        )
        return !badPasswords.contains(inputString)
    }

    private fun checkPasswordGoodLength(inputString: String): Boolean =
        inputString.length >= MIN_PASSWORD_LENGTH

    private fun createFile(inputBytesToSave: ByteArray, filePath: String, fileName: String) {
        val file = File(filePath + fileName)
        file.createNewFile()
        val fileOutputStream = FileOutputStream(file)
        fileOutputStream.write(inputBytesToSave)
        fileOutputStream.close()
    }

    private fun readBytes(context: Context, uri: Uri): ByteArray? =
        context.contentResolver.openInputStream(uri)?.buffered()?.use { it.readBytes() }

    private fun requestPermissions() {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
            EXTERNAL_STORAGE_PERMISSION_CODE
        )
    }

    private fun getFileName(uri: Uri): String? {
        var result: String? = null
        if (uri.scheme == "content") {
            val cursor: Cursor? = contentResolver.query(uri, null, null, null, null)
            cursor.use { _cursor ->
                if (_cursor != null && _cursor.moveToFirst()) {
                    result = _cursor.getString(_cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME))
                }
            }
        }
        if (result == null) {
            result = uri.path
            val cut = result!!.lastIndexOf('/')
            if (cut != -1) {
                result = result?.substring(cut + 1) ?: throw Exception("ALL FAILED MFKA")
            }
        }
        return result
    }

    private fun makeToastIsEmptyPasswordKey() {
        Toast.makeText(this, "Введенная парольная фраза пуста!", Toast.LENGTH_LONG).show()
    }

    private fun makeToastIsEmptyFileName() {
        Toast.makeText(this, "Пустое название файла!", Toast.LENGTH_LONG).show()
    }

    private fun makeToastSuccessEncoded() {
        Toast.makeText(this, "Успешно зашифровано!", Toast.LENGTH_LONG).show()
    }

    private fun makeToastBadPasswordLength() {
        Toast.makeText(
            this,
            "Ваш пароль не удовлетворяет минимальному требованию длины в 6 символов!",
            Toast.LENGTH_LONG
        ).show()
    }

    private fun makeToastBadPasswordEasy() {
        Toast.makeText(this, "Вы ввели слишком простой пароль!", Toast.LENGTH_LONG).show()
    }

    private fun makeToastSuccessDecoded() {
        Toast.makeText(this, "Расшифровано!", Toast.LENGTH_LONG).show()
    }

    private fun makeToastError() {
        Toast.makeText(this, "Произошла непредвиденная ошибка!", Toast.LENGTH_LONG).show()
    }

    private fun makeToastNotSelectedRealization() {
        Toast.makeText(this, "Не выбрана реализация криптоалгоритма!", Toast.LENGTH_LONG).show()
    }

    private companion object {
        const val FILE_SELECT_CODE = 1
        const val EXTERNAL_STORAGE_PERMISSION_CODE = 23
        const val MIN_PASSWORD_LENGTH = 5
    }
}