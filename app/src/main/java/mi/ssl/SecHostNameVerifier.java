package mi.ssl;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;


public class SecHostNameVerifier implements HostnameVerifier {

    @Override
    public boolean verify(String hostname, SSLSession session) {

        boolean verified = false;
        try {
            //the list of certificates identifying the peer with the peer's identity certificate followed by CAs.
            Certificate[] certificate = session.getPeerCertificates();
            LogUtil.i("PeerCertificates length = " + certificate.length );

            //证书链第一个leaf网站证书才有hostName值
            verified = MiPinningTrustManger.verifyHostname(hostname, (X509Certificate) certificate[0]);
            LogUtil.e("hostname verified result = " + verified + " in hostnameVerifier()");

        } catch (SSLPeerUnverifiedException e) {
            e.printStackTrace();
        }
        return verified;
    }
}
