package com.aivpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * Android VPN service that tunnels all device traffic through the AIVPN server.
 *
 * Uses the standard Android VpnService API which provides a TUN file descriptor.
 * The service runs in the foreground with a persistent notification.
 */
class AivpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.aivpn.CONNECT"
        const val ACTION_DISCONNECT = "com.aivpn.DISCONNECT"
        private const val CHANNEL_ID = "aivpn_vpn"
        private const val NOTIFICATION_ID = 1
        private const val TUN_MTU = 1420
        private const val KEEPALIVE_INTERVAL_MS = 10_000L // 10 секунд
        private const val KEEPALIVE_TIMEOUT_MS = 30_000L // 30 секунд без ответа = разрыв
        private const val SOCKET_TIMEOUT_MS = 5_000L // Таймаут для receive
        private const val TAG = "AivpnService"

        // Callback to update the UI from the service
        @Volatile var statusCallback: ((connected: Boolean, status: String) -> Unit)? = null
        @Volatile var trafficCallback: ((uploadBytes: Long, downloadBytes: Long) -> Unit)? = null

        // Whether VPN is currently connected (for UI state restoration)
        @Volatile var isRunning = false
        @Volatile var lastStatusText: String = ""
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var udpSocket: DatagramSocket? = null
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    @Volatile private var connectionGeneration: Long = 0
    @Volatile private var manualDisconnect = false

    // Network callback для отслеживания изменений сети
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    // Текущая сеть для отслеживания реальных изменений
    @Volatile private var currentNetwork: Any? = null

    // Сохраняем параметры подключения для переподключения
    @Volatile private var savedServerAddr: String? = null
    @Volatile private var savedServerKey: String? = null
    @Volatile private var savedPsk: String? = null
    @Volatile private var savedVpnIp: String? = null

    // Traffic counters
    @Volatile private var totalUploadBytes: Long = 0
    @Volatile private var totalDownloadBytes: Long = 0

    // Keepalive tracking
    @Volatile private var lastKeepaliveResponse = 0L
    @Volatile private var keepalivePending = false
    
    // Флаг что сеть изменилась и нужно сбросить backoff при переподключении
    @Volatile private var networkChanged = false
    // Grace period после установки VPN — игнорируем сетевые изменения
    // (Android меняет дефолтную сеть на VPN, что триггерит ложный onAvailable)
    @Volatile private var vpnEstablishedTime = 0L
    private val VPN_GRACE_PERIOD_MS = 5_000L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val server = intent.getStringExtra("server") ?: return START_NOT_STICKY
                val serverKey = intent.getStringExtra("server_key") ?: return START_NOT_STICKY
                val pskBase64 = intent.getStringExtra("psk")
                val vpnIp = intent.getStringExtra("vpn_ip")
                startVpn(server, serverKey, pskBase64, vpnIp)
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_STICKY
    }

    private fun startVpn(serverAddr: String, serverKeyBase64: String, pskBase64: String? = null, vpnIp: String? = null) {
        Log.d(TAG, "startVpn called: server=$serverAddr")
        // Сохраняем параметры для переподключения
        savedServerAddr = serverAddr
        savedServerKey = serverKeyBase64
        savedPsk = pskBase64
        savedVpnIp = vpnIp

        connectionGeneration += 1
        val generation = connectionGeneration
        manualDisconnect = false

        serviceJob?.cancel()
        
        // Register network callback для отслеживания изменений сети
        registerNetworkCallback()

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.notification_connecting)))

        // Reset traffic counters
        totalUploadBytes = 0
        totalDownloadBytes = 0

        serviceJob = serviceScope.launch {
            var attempt = 0
            var backoffMs = 1_000L
            val maxBackoffMs = 60_000L

            while (isActive && connectionGeneration == generation && !manualDisconnect) {
                try {
                    Log.d(TAG, "Connection attempt #${attempt + 1}")
                    statusCallback?.invoke(true, getString(R.string.status_connecting))

                    // Parse server address
                    val parts = serverAddr.split(":")
                    val host = parts[0]
                    val port = parts.getOrElse(1) { "443" }.toInt()

                    // Decode server public key
                    val serverKey = android.util.Base64.decode(
                        serverKeyBase64, android.util.Base64.DEFAULT
                    )
                    if (serverKey.size != 32) {
                        statusCallback?.invoke(false, getString(R.string.error_invalid_key))
                        break
                    }

                    // Decode PSK if provided
                    val psk: ByteArray? = pskBase64?.let {
                        val decoded = android.util.Base64.decode(it, android.util.Base64.DEFAULT)
                        if (decoded.size == 32) decoded else null
                    }

                    // Всегда создаем новый crypto объект при каждом подключении
                    Log.d(TAG, "Creating crypto object")
                    val crypto = AivpnCrypto(serverKey, psk)

                    // Создаем новый UDP сокет
                    Log.d(TAG, "Creating UDP socket to $host:$port")
                    val socket = DatagramSocket()
                    socket.connect(InetSocketAddress(host, port))
                    socket.soTimeout = SOCKET_TIMEOUT_MS.toInt()
                    udpSocket = socket
                    
                    // Protect the UDP socket from being routed through our own VPN
                    protect(socket)
                    
                    // Всегда делаем полный handshake
                    Log.d(TAG, "Sending init handshake packet")
                    val initPacket = crypto.buildInitPacket()
                    socket.send(DatagramPacket(initPacket, initPacket.size))

                    // Wait for ServerHello response
                    Log.d(TAG, "Waiting for ServerHello response")
                    val recvBuf = ByteArray(2048)
                    val response = DatagramPacket(recvBuf, recvBuf.size)
                    socket.receive(response)
                    Log.d(TAG, "ServerHello received, length=${response.length}")

                    // Process ServerHello and complete PFS ratchet
                    val serverHelloData = recvBuf.copyOf(response.length)
                    if (!crypto.processServerHello(serverHelloData)) {
                        statusCallback?.invoke(false, getString(R.string.error_handshake))
                        throw RuntimeException("Handshake failed (ServerHello validation)")
                    }
                    Log.d(TAG, "Handshake successful")
                    
                    // Инициализируем keepalive tracking
                    lastKeepaliveResponse = System.currentTimeMillis()
                    keepalivePending = false
                    // Создаем TUN интерфейс
                    val tunAddress = vpnIp ?: "10.0.0.2"
                    Log.d(TAG, "Establishing TUN interface with address $tunAddress")
                    val builder = Builder()
                        .setSession("AIVPN")
                        .addAddress(tunAddress, 24)
                        .addRoute("0.0.0.0", 0)
                        .addDnsServer("8.8.8.8")
                        .addDnsServer("1.1.1.1")
                        .setMtu(TUN_MTU)
                        .setBlocking(true)

                    vpnInterface = builder.establish()
                        ?: throw Exception("Failed to establish VPN interface")
                    Log.d(TAG, "TUN interface established")
                    vpnEstablishedTime = System.currentTimeMillis()

                    isRunning = true
                    lastStatusText = getString(R.string.status_connected, host)
                    statusCallback?.invoke(true, lastStatusText)
                    updateNotification(getString(R.string.notification_connected, host))

                    val tunFd = vpnInterface!!
                    val localTunIn = FileInputStream(tunFd.fileDescriptor)
                    val localTunOut = FileOutputStream(tunFd.fileDescriptor)
                    tunIn = localTunIn
                    tunOut = localTunOut

                    // Launch three coroutines for bidirectional forwarding/keepalive
                    val tunToUdp = launch { tunToServer(localTunIn, socket, crypto) }
                    val udpToTun = launch { serverToTun(socket, localTunOut, crypto) }
                    val keepaliveLoop = launch { keepaliveToServer(socket, crypto) }

                    // Wait until either direction fails or is cancelled.
                    // If we exit "normally" without CancellationException, treat it as a reconnectable failure.
                    tunToUdp.join()
                    udpToTun.join()
                    keepaliveLoop.join()
                    throw RuntimeException("Tunnel forwarding stopped")

                } catch (e: CancellationException) {
                    // Normal shutdown / service stop.
                    Log.d(TAG, "Service cancelled")
                    break
                } catch (e: Exception) {
                    attempt += 1
                    Log.e(TAG, "Connection error: ${e.message}", e)
                    
                    // Make sure all child loops are stopped before cleanup/retry.
                    coroutineContext.cancelChildren()
                    
                    // Закрываем TUN потоки ПЕРЕД закрытием TUN — это разблокирует
                    // застрявшие read/write в старых корутинах
                    try { tunIn?.close() } catch (_: Exception) {}
                    try { tunOut?.close() } catch (_: Exception) {}
                    tunIn = null
                    tunOut = null
                    
                    // Закрываем UDP сокет
                    try { udpSocket?.close() } catch (_: Exception) {}
                    udpSocket = null
                    
                    // Всегда закрываем TUN — при реконнекте создадим новый.
                    // Это гарантирует что старые корутины разблокируются (fd закрыт)
                    // и новые корутины получат чистый fd.
                    try { vpnInterface?.close() } catch (_: Exception) {}
                    vpnInterface = null

                    if (connectionGeneration != generation || manualDisconnect) {
                        isRunning = false
                        lastStatusText = getString(R.string.status_error, e.message ?: "unknown")
                        statusCallback?.invoke(false, lastStatusText)
                        break
                    }

                    // При смене сети сбрасываем backoff для быстрого переподключения
                    if (networkChanged) {
                        networkChanged = false
                        backoffMs = 1_000L
                        attempt = 0
                        Log.d(TAG, "Network changed — backoff reset to 1s")
                    }

                    val delayMs = (backoffMs).coerceAtMost(maxBackoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(maxBackoffMs)

                    // Показываем reconnecting но НЕ disconnected
                    // isRunning остается true!
                    lastStatusText = getString(R.string.status_reconnecting)
                    statusCallback?.invoke(true, lastStatusText) // connected = true!
                    updateNotification(getString(R.string.notification_connecting))
                    Log.d(TAG, "Reconnecting in ${delayMs}ms")
                    delay(delayMs)
                }
            }

            isRunning = false
            cleanup()
            if (serviceJob == coroutineContext[Job]) {
                serviceJob = null
            }
            if (connectionGeneration == generation && !manualDisconnect) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    /**
     * TUN → Server: read IP packets from the device, encrypt with AIVPN protocol,
     * send as UDP datagrams to the server.
     * Проверяет что сокет еще активен перед отправкой.
     */
    private suspend fun tunToServer(
        tunIn: FileInputStream,
        socket: DatagramSocket,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        val buf = ByteArray(TUN_MTU + 100) // Extra space for IP headers
        while (isActive) {
            try {
                val n = tunIn.read(buf)
                if (n > 0) {
                    // Проверяем что сокет еще активен перед отправкой
                    if (socket.isClosed) {
                        throw RuntimeException("UDP socket closed unexpectedly")
                    }
                    
                    val ipPacket = buf.copyOf(n)
                    val encrypted = crypto.encryptDataPacket(ipPacket)
                    socket.send(DatagramPacket(encrypted, encrypted.size))
                    totalUploadBytes += n
                    trafficCallback?.invoke(totalUploadBytes, totalDownloadBytes)
                }
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    /**
     * Server → TUN: receive encrypted UDP datagrams from the server, decrypt,
     * extract the IP packet, write it to the TUN device.
     * Также отслеживает keepalive ответы от сервера.
     */
    private suspend fun serverToTun(
        socket: DatagramSocket,
        tunOut: FileOutputStream,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        val buf = ByteArray(TUN_MTU + 200) // Extra space for VPN overhead
        while (isActive) {
            try {
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)
                
                // Любой пакет от сервера означает что соединение живо
                lastKeepaliveResponse = System.currentTimeMillis()
                keepalivePending = false
                
                val data = buf.copyOf(pkt.length)
                val decrypted = crypto.decryptDataPacket(data)
                if (decrypted != null && decrypted.isNotEmpty()) {
                    tunOut.write(decrypted)
                    totalDownloadBytes += decrypted.size
                    trafficCallback?.invoke(totalUploadBytes, totalDownloadBytes)
                }
            } catch (e: SocketTimeoutException) {
                // Таймаут при receive - это нормально, просто продолжаем
                // Но проверяем не слишком ли долго нет ответа от сервера
                val timeSinceLastResponse = System.currentTimeMillis() - lastKeepaliveResponse
                if (timeSinceLastResponse > KEEPALIVE_TIMEOUT_MS * 2) {
                    throw RuntimeException("Server not responding - connection lost")
                }
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    /**
     * Keep the UDP mapping and server session alive while the tunnel is idle.
     * Также проверяем что соединение живо через таймауты.
     */
    private suspend fun keepaliveToServer(
        socket: DatagramSocket,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        while (isActive) {
            try {
                delay(KEEPALIVE_INTERVAL_MS)
                
                // Проверяем не было ли слишком долгого отсутствия ответа
                val timeSinceLastResponse = System.currentTimeMillis() - lastKeepaliveResponse
                if (timeSinceLastResponse > KEEPALIVE_TIMEOUT_MS) {
                    throw RuntimeException("Keepalive timeout - connection lost")
                }
                
                keepalivePending = true
                val keepalive = crypto.buildKeepalivePacket()
                socket.send(DatagramPacket(keepalive, keepalive.size))
            } catch (e: SocketTimeoutException) {
                if (isActive) throw RuntimeException("Socket timeout in keepalive", e)
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    private fun stopVpn() {
        manualDisconnect = true
        connectionGeneration += 1
        serviceJob?.cancel()
        serviceJob = null
        cleanup()
        isRunning = false
        lastStatusText = getString(R.string.status_disconnected)
        statusCallback?.invoke(false, lastStatusText)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    /**
     * Register network callback для отслеживания изменений DEFAULT сети.
     * Используем registerDefaultNetworkCallback чтобы получать события только
     * при смене дефолтной сети (WiFi <-> mobile), а не для каждой сети с интернетом.
     */
    private fun registerNetworkCallback() {
        try {
            // Сначала отменяем старый callback чтобы избежать дублирования
            unregisterNetworkCallback()
            
            val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    super.onAvailable(network)
                    Log.d(TAG, "Default network available: $network")
                    
                    // Если VPN ещё не подключен — просто запоминаем сеть, НЕ реконнектим.
                    // onAvailable вызывается сразу при регистрации callback.
                    if (!isRunning) {
                        currentNetwork = network
                        return
                    }
                    
                    // В течение grace period после установки VPN игнорируем сетевые изменения.
                    // Android меняет дефолтную сеть на VPN — это НЕ реальная смена сети.
                    val timeSinceVpn = System.currentTimeMillis() - vpnEstablishedTime
                    if (timeSinceVpn < VPN_GRACE_PERIOD_MS) {
                        Log.d(TAG, "Ignoring network change — within VPN grace period (${timeSinceVpn}ms)")
                        currentNetwork = network
                        return
                    }
                    
                    // Реконнектим ТОЛЬКО если сеть действительно изменилась
                    if (network != currentNetwork) {
                        Log.d(TAG, "Network changed: $currentNetwork -> $network — reconnecting")
                        currentNetwork = network
                        networkChanged = true
                        triggerNetworkReconnect()
                    } else {
                        Log.d(TAG, "Same network $network — no reconnect needed")
                    }
                }

                override fun onLost(network: Network) {
                    super.onLost(network)
                    Log.d(TAG, "Default network lost: $network")
                    currentNetwork = null
                    // НЕ закрываем сокет сразу!
                    // Ждём onAvailable() с новой сетью. Если новая сеть не появится,
                    // keepalive timeout (30с) сам закроет соединение.
                }
            }
            
            // registerDefaultNetworkCallback — только для дефолтной сети,
            // не для каждой сети с NET_CAPABILITY_INTERNET
            connectivityManager.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback", e)
        }
    }

    /**
     * Форсирует переподключение при изменении сети.
     * Закрывает UDP сокет чтобы основной цикл переподключился.
     */
    private fun triggerNetworkReconnect() {
        // Сбрасываем keepalive чтобы цикл обнаружил проблему
        lastKeepaliveResponse = 0
        keepalivePending = true
        
        // Закрываем UDP сокет чтобы основной цикл обнаружил проблему
        try {
            udpSocket?.close()
        } catch (e: Exception) {
            // Игнорируем
        }
        udpSocket = null
    }

    /**
     * Unregister network callback.
     */
    private fun unregisterNetworkCallback() {
        try {
            networkCallback?.let { callback ->
                val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                connectivityManager.unregisterNetworkCallback(callback)
                networkCallback = null
            }
        } catch (e: Exception) {
            // Игнорируем ошибки при отмене
        }
    }

    private fun cleanup() {
        try { tunIn?.close() } catch (_: Exception) {}
        try { tunOut?.close() } catch (_: Exception) {}
        try { vpnInterface?.close() } catch (_: Exception) {}
        try { udpSocket?.close() } catch (_: Exception) {}
        tunIn = null
        tunOut = null
        vpnInterface = null
        udpSocket = null
        unregisterNetworkCallback()
    }

    override fun onDestroy() {
        serviceJob?.cancel()
        cleanup()
        isRunning = false
        super.onDestroy()
    }

    // ──────────── Notifications ────────────

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_desc)
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("AIVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
