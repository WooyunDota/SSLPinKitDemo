package mi.ssl;

import android.net.http.X509TrustManagerExtensions;
import android.os.Build;
import android.support.annotation.NonNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

public class MiPinningTrustManger implements X509TrustManager {
    private X509TrustManagerExtensions baselineTrustManager;
    private final String serverHostname;
    private static final int ALT_DNS_NAME = 2;
    private final static List<String> PinningCA = new ArrayList<String>(){{
        //根证书锁定godaddy,现役证书G1,20340630
        //GoDaddy Class 2 Certification Authority Root Certificate
        //c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4
        add("c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4");
        //根证书锁定godaddy,现役证书G2,20380101
        //GoDaddy Class 2 Certification Authority Root Certificate - G2
        //45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda
        add("45140b3247eb9cc8c5b4f0d7b53091f73292089e6e5a63e2749dd3aca9198eda");
        //根证书锁定DigiCert,备份证书1,EV类型,20311110
        //DigiCert High Assurance EV Root CA
        //7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
        add("7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf");
        //根证书锁定DigiCert,备份证书2, OV/DV 类型,20311110
        //DigiCert Global Root CA
        //cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f
        add("cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f");
    }};

    public MiPinningTrustManger(@NonNull String serverHostname) {

        this.serverHostname = serverHostname;

        if (Build.VERSION.SDK_INT < 17) {
            // No pinning validation at all for API level < 17
            // Because X509TrustManagerExtensions is not available
            this.baselineTrustManager = null;
        } else {
            // We use the default trust manager so we can perform regular SSL validation and we wrap
            // it in the Android-specific X509TrustManagerExtensions, which provides an API to
            // compute the cleaned/verified server certificate chain that we eventually need for
            // pinning validation. Also the X509TrustManagerExtensions provides a
            // checkServerTrusted() where the hostname can be supplied, allowing it to call the
            // (system) RootTrustManager on Android N
            try {
                this.baselineTrustManager = new X509TrustManagerExtensions(SystemTrustManager.getInstance());
            } catch (IllegalArgumentException e) {
                e.printStackTrace();
            }
        }

    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        boolean didChainValidationFail = false;
        boolean didPinningValidationFail = false;


        // Store the received chain so we can send it later in a report if path validation fails
        List<X509Certificate> servedServerChain = Arrays.asList((X509Certificate [])chain);
        // List<X509Certificate> validatedServerChain = servedServerChain;


        int i =  0 ;
        for (X509Certificate tmp:chain
                ) {
            LogUtil.i("cerHash + " + i + " >>> " + SHA256(tmp.getEncoded()));
            i++;
        }

        //#8: ObjectId: 2.5.29.17 Criticality=false
        //SubjectAlternativeName [
        //  DNSName: *.account.xiaomi.com
        //  DNSName: account.xiaomi.com

        //参考TrustKit代码先验一次hostName有备无患,证书链第一个站点证书取SubjectAlternativeName对比网站HostName
        if(!verifyHostname(serverHostname,chain[0])){
            didChainValidationFail = true;
        }


        // Then do the system's SSL validation and try to compute the verified chain, which includes
        // the root certificate from the Android trust store and removes unrelated
        // extra certificates an attacker might add: https://koz.io/pinning-cve-2016-2402/
        if (baselineTrustManager!=null){
            try {

                servedServerChain = baselineTrustManager.checkServerTrusted(chain, authType,
                        serverHostname);

                int j =  0 ;
                for (X509Certificate tmp:servedServerChain
                        ) {
                    LogUtil.i("cerHash + " + j + " >>> " + SHA256(tmp.getEncoded()));
                    j++;
                }

            } catch (CertificateException e) {
                if ((Build.VERSION.SDK_INT >= 24)
                        && (e.getMessage().startsWith("Pin verification failed"))) {
                    // A pinning failure triggered by the Android N netsec policy
                    // This can only happen after path validation was successful
                    didPinningValidationFail = true;
                } else {
                    // Path or hostname validation failed
                    didChainValidationFail = true;
                }
            }

        }

        LogUtil.e("chain length =  " + chain.length + " | servedServerChain length = " + servedServerChain.size());

        if (didChainValidationFail){

            throw new CertificateException("Certificate validation failed for " + serverHostname);
        }else {
            LogUtil.e("hostName verified successed in checkServerTrusted()");
        }

        String IntermediateCerHash = SHA256(servedServerChain.get(1).getEncoded()).toLowerCase();
        String RootCerHash = SHA256(servedServerChain.get(servedServerChain.size()-1).getEncoded()).toLowerCase();
//
//        if (!BuildConfig.DEBUG){ //debug版本不锁定证书,release版本锁定,以便测试.
//
//        }
        if (!PinningCA.contains(RootCerHash)){
            didPinningValidationFail = true;
            LogUtil.e("pinning fail IntermediateCerHash hash = "+IntermediateCerHash);
            LogUtil.e("pinning fail RootCerHash hash = "+RootCerHash);

        }


        if (didPinningValidationFail){
            throw new CertificateException("ssl pinning failed");
        }else {
            LogUtil.e("ssl pinning successed");
        }

    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }

    /** Returns true if {@code certificate} matches {@code hostname}. */
    public static  boolean verifyHostname(String hostname, X509Certificate certificate) {
        hostname = hostname.toLowerCase(Locale.US);
        boolean hasDns = false;
        List<String> altNames = getSubjectAltNames(certificate, ALT_DNS_NAME);
        LogUtil.i("hostname altNames size " + altNames.size());

        for (int i = 0, size = altNames.size(); i < size; i++) {
            LogUtil.i("hostname altNames "+i+" = " + altNames.get(i));

            hasDns = true;
            if (verifyHostname(hostname, altNames.get(i))) {
                return true;
            }
        }

        if (!hasDns) {
            X500Principal principal = certificate.getSubjectX500Principal();
            // RFC 2818 advises using the most specific name for matching.
            String cn = new DistinguishedNameParser(principal).findMostSpecific("cn");
            if (cn != null) {
                return verifyHostname(hostname, cn);
            }
        }

        return false;
    }
    private static boolean verifyHostname(String hostname, String pattern) {
        // Basic sanity checks
        // Check length == 0 instead of .isEmpty() to support Java 5.
        if ((hostname == null) || (hostname.length() == 0) || (hostname.startsWith("."))
                || (hostname.endsWith(".."))) {
            // Invalid domain name
            return false;
        }
        if ((pattern == null) || (pattern.length() == 0) || (pattern.startsWith("."))
                || (pattern.endsWith(".."))) {
            // Invalid pattern/domain name
            return false;
        }

        // Normalize hostname and pattern by turning them into absolute domain names if they are not
        // yet absolute. This is needed because server certificates do not normally contain absolute
        // names or patterns, but they should be treated as absolute. At the same time, any hostname
        // presented to this method should also be treated as absolute for the purposes of matching
        // to the server certificate.
        //   www.android.com  matches www.android.com
        //   www.android.com  matches www.android.com.
        //   www.android.com. matches www.android.com.
        //   www.android.com. matches www.android.com
        if (!hostname.endsWith(".")) {
            hostname += '.';
        }
        if (!pattern.endsWith(".")) {
            pattern += '.';
        }
        // hostname and pattern are now absolute domain names.

        pattern = pattern.toLowerCase(Locale.US);
        // hostname and pattern are now in lower case -- domain names are case-insensitive.

        if (!pattern.contains("*")) {
            // Not a wildcard pattern -- hostname and pattern must match exactly.
            return hostname.equals(pattern);
        }
        // Wildcard pattern

        // WILDCARD PATTERN RULES:
        // 1. Asterisk (*) is only permitted in the left-most domain name label and must be the
        //    only character in that label (i.e., must match the whole left-most label).
        //    For example, *.example.com is permitted, while *a.example.com, a*.example.com,
        //    a*b.example.com, a.*.example.com are not permitted.
        // 2. Asterisk (*) cannot match across domain name labels.
        //    For example, *.example.com matches test.example.com but does not match
        //    sub.test.example.com.
        // 3. Wildcard patterns for single-label domain names are not permitted.

        if ((!pattern.startsWith("*.")) || (pattern.indexOf('*', 1) != -1)) {
            // Asterisk (*) is only permitted in the left-most domain name label and must be the only
            // character in that label
            return false;
        }

        // Optimization: check whether hostname is too short to match the pattern. hostName must be at
        // least as long as the pattern because asterisk must match the whole left-most label and
        // hostname starts with a non-empty label. Thus, asterisk has to match one or more characters.
        if (hostname.length() < pattern.length()) {
            // hostname too short to match the pattern.
            return false;
        }

        if ("*.".equals(pattern)) {
            // Wildcard pattern for single-label domain name -- not permitted.
            return false;
        }

        // hostname must end with the region of pattern following the asterisk.
        String suffix = pattern.substring(1);
        if (!hostname.endsWith(suffix)) {
            // hostname does not end with the suffix
            return false;
        }

        // Check that asterisk did not match across domain name labels.
        int suffixStartIndexInHostname = hostname.length() - suffix.length();
        if ((suffixStartIndexInHostname > 0)
                && (hostname.lastIndexOf('.', suffixStartIndexInHostname - 1) != -1)) {
            // Asterisk is matching across domain name labels -- not permitted.
            return false;
        }

        // hostname matches pattern
        return true;
    }

    private static List<String> getSubjectAltNames(X509Certificate certificate, int type) {
        List<String> result = new ArrayList<>();
        try {
            Collection<?> subjectAltNames = certificate.getSubjectAlternativeNames();
            if (subjectAltNames == null) {
                return Collections.emptyList();
            }
            for (Object subjectAltName : subjectAltNames) {
                List<?> entry = (List<?>) subjectAltName;
                if (entry == null || entry.size() < 2) {
                    continue;
                }
                Integer altNameType = (Integer) entry.get(0);
                if (altNameType == null) {
                    continue;
                }
                if (altNameType == type) {
                    String altName = (String) entry.get(1);
                    if (altName != null) {
                        result.add(altName);
                    }
                }
            }
            return result;
        } catch (CertificateParsingException e) {
            return Collections.emptyList();
        }
    }
    public static String SHA256(final byte[]  strText)
    {
        return SHA(strText, "SHA-256");
    }

    public static  String SHA(final byte[] strText, final String strType)
    {
        String strResult = null;

        if (strText != null )
        {
            try
            {

                MessageDigest messageDigest = MessageDigest.getInstance(strType);
                messageDigest.update(strText);
                byte byteBuffer[] = messageDigest.digest();
                StringBuffer strHexString = new StringBuffer();
                for (int i = 0; i < byteBuffer.length; i++)
                {
                    String hex = Integer.toHexString(0xff & byteBuffer[i]);
                    if (hex.length() == 1)
                    {
                        strHexString.append('0');
                    }
                    strHexString.append(hex);
                }
                strResult = strHexString.toString();
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }
        }

        return strResult;
    }
}
