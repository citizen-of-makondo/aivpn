package com.aivpn.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.aivpn.client.databinding.ActivityMainBinding
import org.json.JSONObject

/**
 * Main screen — server address, public key, connect/disconnect button,
 * connection timer, traffic stats, and EN/RU language toggle.
 *
 * v0.3.0: Uses EncryptedSharedPreferences for secure key storage.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var isConnected = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, getString(R.string.error_vpn_denied), Toast.LENGTH_SHORT).show()
        }
    }

    // Connection timer
    private val timerHandler = Handler(Looper.getMainLooper())
    private var connectionStartTime = 0L
    private val timerRunnable = object : Runnable {
        override fun run() {
            if (isConnected && connectionStartTime > 0) {
                val elapsed = (System.currentTimeMillis() - connectionStartTime) / 1000
                val h = elapsed / 3600
                val m = (elapsed % 3600) / 60
                val s = elapsed % 60
                binding.textTimer.text = String.format("%02d:%02d:%02d", h, m, s)
                binding.textDuration.text = String.format("%02d:%02d", h * 60 + m, s)
                timerHandler.postDelayed(this, 1000)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Restore saved connection key from encrypted storage
        binding.editConnectionKey.setText(SecureStorage.loadConnectionKey(this))

        // Update language button label
        updateLanguageButton()

        binding.btnConnect.setOnClickListener {
            if (isConnected) {
                disconnect()
            } else {
                connect()
            }
        }

        binding.btnLanguage.setOnClickListener {
            toggleLanguage()
        }

        // Restore connection state if service is already running
        if (AivpnService.isRunning) {
            isConnected = true
            updateUI(true, AivpnService.lastStatusText)
        }
    }

    override fun onResume() {
        super.onResume()
        // Register callbacks when activity becomes visible.
        // Using onResume/onPause instead of onCreate/onDestroy prevents the race condition
        // where a destroyed (rotated) Activity nullifies callbacks registered by the new one.
        AivpnService.statusCallback = { connected, statusText ->
            runOnUiThread {
                isConnected = connected
                updateUI(connected, statusText)
            }
        }

        AivpnService.trafficCallback = { uploadBytes, downloadBytes ->
            runOnUiThread {
                binding.textUpload.text = formatBytes(uploadBytes)
                binding.textDownload.text = formatBytes(downloadBytes)
            }
        }

        // Restore UI state if service is already running (e.g. after returning from
        // VPN permission dialog or screen rotation)
        if (AivpnService.isRunning) {
            isConnected = true
            updateUI(true, AivpnService.lastStatusText)
        }
    }

    override fun onPause() {
        super.onPause()
        // Unregister callbacks when activity is no longer in foreground.
        // Only nullify if activity is actually finishing (not just pausing for
        // VPN permission dialog, multi-window, etc.)
        if (isFinishing) {
            AivpnService.statusCallback = null
            AivpnService.trafficCallback = null
        }
    }

    /**
     * Parse connection key: aivpn://BASE64URL({"s":"host:port","k":"...","p":"...","i":"..."})
     * Returns (server, serverKey, psk, vpnIp) or null on failure.
     */
    private fun parseConnectionKey(key: String): Array<String>? {
        val raw = key.trim()
        val payload = if (raw.startsWith("aivpn://")) raw.removePrefix("aivpn://") else raw
        return try {
            // Decode URL-safe base64 (no padding)
            val jsonBytes = android.util.Base64.decode(payload,
                android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP)
            val json = JSONObject(String(jsonBytes))
            val server = json.getString("s")
            val serverKey = json.getString("k")
            val psk = json.getString("p")
            val vpnIp = json.getString("i")
            arrayOf(server, serverKey, psk, vpnIp)
        } catch (_: Exception) {
            null
        }
    }

    private fun connect() {
        val connectionKey = binding.editConnectionKey.text.toString().trim()
        if (connectionKey.isEmpty()) {
            Toast.makeText(this, getString(R.string.error_fill_fields), Toast.LENGTH_SHORT).show()
            return
        }

        val parsed = parseConnectionKey(connectionKey)
        if (parsed == null) {
            Toast.makeText(this, getString(R.string.error_invalid_connection_key), Toast.LENGTH_SHORT).show()
            return
        }

        // Save connection key to encrypted storage
        SecureStorage.saveConnectionKey(this, connectionKey)

        // Request VPN permission from the system
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun disconnect() {
        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }

    private fun startVpnService() {
        val connectionKey = binding.editConnectionKey.text.toString().trim()
        val parsed = parseConnectionKey(connectionKey) ?: return
        val (server, serverKey, psk, vpnIp) = parsed

        val intent = Intent(this, AivpnService::class.java).apply {
            action = AivpnService.ACTION_CONNECT
            putExtra("server", server)
            putExtra("server_key", serverKey)
            putExtra("psk", psk)
            putExtra("vpn_ip", vpnIp)
        }
        startForegroundService(intent)
        updateUI(true, getString(R.string.status_connecting))
    }

    private fun updateUI(connected: Boolean, statusText: String) {
        isConnected = connected
        binding.btnConnect.text = getString(
            if (connected) R.string.btn_disconnect else R.string.btn_connect
        )
        binding.btnConnect.setBackgroundColor(
            getColor(if (connected) R.color.disconnect else R.color.accent)
        )
        binding.textStatus.text = statusText
        binding.statusDot.setBackgroundResource(
            if (connected) R.drawable.dot_green else R.drawable.dot_grey
        )

        // Show/hide stats and timer
        val statsVisibility = if (connected) View.VISIBLE else View.GONE
        binding.textTimer.visibility = statsVisibility
        binding.statsRow.visibility = statsVisibility

        // Lock/unlock input fields while connected
        binding.editConnectionKey.isEnabled = !connected

        // Timer management
        if (connected && connectionStartTime == 0L) {
            connectionStartTime = System.currentTimeMillis()
            timerHandler.post(timerRunnable)
        } else if (!connected) {
            connectionStartTime = 0L
            timerHandler.removeCallbacks(timerRunnable)
            binding.textTimer.text = "00:00:00"
            binding.textUpload.text = "0 B"
            binding.textDownload.text = "0 B"
            binding.textDuration.text = "00:00"
        }
    }

    private fun toggleLanguage() {
        val currentLang = SecureStorage.loadLanguage(this)
        val newLang = if (currentLang == "en") "ru" else "en"

        SecureStorage.saveLanguage(this, newLang)

        val localeList = LocaleListCompat.forLanguageTags(newLang)
        AppCompatDelegate.setApplicationLocales(localeList)
    }

    private fun updateLanguageButton() {
        // Apply saved language on startup
        val savedLang = SecureStorage.loadLanguage(this)
        if (savedLang != "en") {
            val localeList = LocaleListCompat.forLanguageTags(savedLang)
            AppCompatDelegate.setApplicationLocales(localeList)
        }

        val currentLang = savedLang.uppercase()
        binding.btnLanguage.text = if (currentLang == "EN") "EN → RU" else "RU → EN"
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> String.format("%.1f KB", bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
            else -> String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    override fun onDestroy() {
        timerHandler.removeCallbacks(timerRunnable)
        super.onDestroy()
    }
}
