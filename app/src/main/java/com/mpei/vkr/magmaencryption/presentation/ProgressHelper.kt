package com.mpei.vkr.magmaencryption.presentation

import android.os.Handler
import android.widget.ProgressBar

class ProgressHelper(
    private val progressBar: ProgressBar,
    private val handler: Handler
) {

    fun setProgressToBarInAnotherThread(progress: Int) {
        handler.post {
            progressBar.progress = if (progress == 100) 0 else progress
        }
    }
}
