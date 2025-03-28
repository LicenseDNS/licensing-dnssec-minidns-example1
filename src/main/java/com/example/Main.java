package com.example;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import org.minidns.dnsmessage.DnsMessage.RESPONSE_CODE;
import org.minidns.hla.DnssecResolverApi;
import org.minidns.hla.ResolverResult;
import org.minidns.record.TXT;

/**
 * Example using minidns library. Example license key and product is valid, just
 * run to get the output.
 */
public class Main {

    // product Id from https://manager.licensedns.net
    private static final String PRODUCT_ID = "ADA14AE9-08A8-4AE2-B69E-AAE277B8346F";

    // license key example, normally ask to user, and use obtained license key
    private static final String LICENSE_KEY = "5F32A-UN7KF-UE9V8-AW3NS";

    public static void main(String[] args) {
        String activation = "a"; // action activation
        String deactivation = "d"; // action deactivation

        String domain = sha256Hex(LICENSE_KEY + PRODUCT_ID).substring(0, 32); // key and product hash
        String fingerprint = "some-fingerprint"; // fingerprint, device id, anything max 32 chars
        String mainDomain = "q.licensedns.net.";

        // concanate all to form query domain
        String queryAddress = activation + "." + domain + "." + fingerprint + "." + mainDomain;

        try {
            ResolverResult<TXT> result = DnssecResolverApi.INSTANCE.resolve(
                    queryAddress,
                    TXT.class);
            if (!result.wasSuccessful()) {
                RESPONSE_CODE responseCode = result.getResponseCode();
                // Perform error handling.
                return;
            }
            if (!result.isAuthenticData()) {
                // Response was not secured with DNSSEC.
                return;
            }
            Set<TXT> answers = result.getAnswers();
            for (TXT txt : answers) {
                // TXT records received check "result" line, and use other values as you like.
                System.out.println(txt.getText());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // utility to calculate hash
    private static String sha256Hex(String msg) {
        if (msg != null) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedhash = digest.digest(msg.getBytes(StandardCharsets.UTF_8));

                return bytesToHex(encodedhash);
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }
        }

        return null;
    }

    // utility to convert hash to HEX chars
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = "0123456789ABCDEF".toCharArray()[v >>> 4];
            hexChars[j * 2 + 1] = "0123456789ABCDEF".toCharArray()[v & 0x0F];
        }

        return new String(hexChars);
    }
}
