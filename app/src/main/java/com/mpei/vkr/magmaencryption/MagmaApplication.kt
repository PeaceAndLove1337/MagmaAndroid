package com.mpei.vkr.magmaencryption

import android.app.Application
import java.io.File

class MagmaApplication : Application() {

    init {
        magmaApp = this
    }

    override fun onCreate() {
        super.onCreate()
        val encodedDir = File(takeApplicationEncodedFilesPath())
        val decodedDir = File(takeApplicationDecodedFilesPath())
        if (!encodedDir.exists())
            encodedDir.mkdir()
        if (!decodedDir.exists())
            decodedDir.mkdir()
    }

    companion object {
        private lateinit var magmaApp: MagmaApplication
        private fun takeApplicationExternalPath(): String =
            magmaApp.getExternalFilesDir(null).toString()

        fun takeApplicationEncodedFilesPath(): String = "${takeApplicationExternalPath()}/Encoded"
        fun takeApplicationDecodedFilesPath(): String = "${takeApplicationExternalPath()}/Decoded"
    }
}