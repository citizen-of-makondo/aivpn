import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]

        let ipv6 = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]

        let dns = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dns.matchDomains = [""]

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = ipv4
        settings.ipv6Settings = ipv6
        settings.dnsSettings = dns
        settings.mtu = 1346 as NSNumber

        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }
}
