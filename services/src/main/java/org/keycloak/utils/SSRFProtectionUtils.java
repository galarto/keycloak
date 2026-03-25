package org.keycloak.utils;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

public class SSRFProtectionUtils {

    protected static final String CLOUD_METADATA_IP = "169.254.169.254";
    public static void validate(URI uri) {
        if (uri == null) {
            throw new IllegalArgumentException("URI is null");
        }

        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http")
                && !scheme.equalsIgnoreCase("https"))) {
            throw new SecurityException("Invalid scheme: " + scheme);
        }

        String host = uri.getHost();
        if (host == null) {
            throw new SecurityException("Host is null");
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);

            for (InetAddress address : addresses) {
                validateAddress(address);
            }
        } catch (UnknownHostException e) {
            throw new SecurityException("DNS resolution failed for " + host, e);
        }
    }

    private static void validateAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
            || address.isLoopbackAddress()
            || address.isLinkLocalAddress()
            || address.isSiteLocalAddress()
            || address.isMulticastAddress()) {
            throw new SecurityException("Blocked address: " + address);
        }

        String ip = address.getHostAddress();

        if (ip.equals(CLOUD_METADATA_IP)) {
            throw new SecurityException("Blocked metadata endpoint");
        }
    }
}
