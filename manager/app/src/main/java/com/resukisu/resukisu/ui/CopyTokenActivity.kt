package com.resukisu.resukisu.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.resukisu.resukisu.R

/**
 * WebKSU：无界面剪贴板写入 Activity。
 *
 * 由 ksud 内嵌网页服务 / 模块 service.sh 通过显式组件启动：
 *   am start -n com.shichumo.webksu/com.resukisu.resukisu.ui.CopyTokenActivity --es text <令牌>
 *
 * 只接受 64 位十六进制令牌，或带 ?t=<64hex> 的入口 URL，避免被其它应用当成
 * 任意剪贴板写入器；root 守护进程本身没有剪贴板权限，所以借这个前台 Activity 写。
 */
class CopyTokenActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // getLaunchedFromUid() 在不少 ROM 上对 am start 返回 -1（UNKNOWN），
        // 所以未知调用方放行，只拦明确来自普通应用的调用
        val fromUid = launchedFromUid
        if (fromUid != -1 && fromUid != 0 && fromUid != 2000 && fromUid != applicationInfo.uid) {
            Log.w(TAG, "CopyTokenActivity: rejected caller uid=$fromUid")
            finish()
            return
        }
        val raw = intent?.getStringExtra("text")?.trim().orEmpty()
        val token = extractToken(raw)
        if (token == null) {
            Log.w(TAG, "CopyTokenActivity: no valid token in intent")
            finish()
            return
        }
        try {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText(getString(R.string.webksu_token_clip_label), token))
            Toast.makeText(this, getString(R.string.webksu_token_copied), Toast.LENGTH_SHORT).show()
            Log.i(TAG, "CopyTokenActivity: token copied to clipboard")
        } catch (e: Throwable) {
            Log.e(TAG, "CopyTokenActivity: copy failed: ${e.message}")
            Toast.makeText(
                this,
                getString(R.string.webksu_token_copy_failed, e.message ?: "unknown"),
                Toast.LENGTH_SHORT
            ).show()
        }
        finish()
    }

    private fun extractToken(raw: String): String? {
        if (HEX64.matches(raw)) return raw.lowercase()
        val m = URL_TOKEN.find(raw) ?: return null
        return m.groupValues[1].lowercase()
    }

    companion object {
        private const val TAG = "WebKSU"
        private val HEX64 = Regex("^[0-9a-fA-F]{64}$")
        private val URL_TOKEN = Regex("[?&]t=([0-9a-fA-F]{64})")
    }
}
