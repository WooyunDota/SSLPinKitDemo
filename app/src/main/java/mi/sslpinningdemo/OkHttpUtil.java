package mi.sslpinningdemo;


import android.accounts.AccountManager;
import android.content.Intent;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import mi.ssl.MiPinningTrustManger;
import mi.ssl.SecHostNameVerifier;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * Created by magic on 2018/3/29.
 *
 *Godaddy G1
 * 03-29 16:08:22.613 9155-9212/mi.sslpinningdemo E/pinningdemo: certificate chain length =  4
 03-29 16:08:22.614 9155-9212/mi.sslpinningdemo E/pinningdemo: cerHash 0 >>> 15022e1f82db2c49d430368af3530294b9dabca0269b66fba41175c0f4e26d2b 网站证书
 03-29 16:08:22.614 9155-9212/mi.sslpinningdemo E/pinningdemo: cerHash 1 >>> 973a41276ffd01e027a2aad49e34c37846d3e976ff6a620b6712e33832041aa6 godaddy中级证书G2
 03-29 16:08:22.615 9155-9212/mi.sslpinningdemo E/pinningdemo: cerHash 2 >>> 3a2fbe92891e57fe05d57087f48e730f17e5a5f53ef403d618e5b74d7a7e6ecb G1 至 G2 的交叉证书
 03-29 16:08:22.615 9155-9212/mi.sslpinningdemo E/pinningdemo: cerHash 3 >>> c3846bf24b9e93ca64274c0ec67c1ecc5e024ffcacd2d74019350e81fe546ae4 GoDaddy 第 2 级证书颁发机构根证书

 Godaddy G2
 15022e1f82db2c49d430368af3530294b9dabca0269b66fba41175c0f4e26d2b
 973a41276ffd01e027a2aad49e34c37846d3e976ff6a620b6712e33832041aa6
 45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA

 03-29 16:08:22.628 9155-9212/mi.sslpinningdemo E/pinningdemo: hostname = account.xiaomi.com

 DigiCert EV
 www.digicert.com
 cerHash + 0 >>> 23fcae8b41ddacefdf7179b3f85272b2e323ae469022baca8f30b0aab8fa2074
 cerHash + 1 >>> 403e062a2653059113285baf80a0d4ae422c848c9f78fad01fc94bc5b87fef1a
 cerHash + 2 >>> 7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
 */

public class OkHttpUtil {

    public static final MediaType FORM = MediaType.parse("application/x-www-form-urlencoded; charset=utf-8");

    public static String serverHostname = "www.mi.com";
    private static final OkHttpClient okHttpClient =
            new OkHttpClient();



    public static String get(String url){
        Request request =
                new Request.Builder()
                        .url(url)
                        .build();
        Response response = null;
        try {
            response = getSecPinningClient().newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        if (response.isSuccessful()){
            String ret = null;
            try {
                ret=  response.body().string();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return ret;
        }else {
            return String.valueOf(response.code());
        }

    }


    public static String post(String url,String body){
        Request request =
                new Request.Builder()
                        .url(url)
                        .post(RequestBody.create(FORM,body))
                        .build();
        Response  response = null;
        try {
            response = okHttpClient.newCall(request).execute();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (response.isSuccessful()){
            String ret = null;
            try {
                ret=  response.body().string();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return ret;
        }else {
            return String.valueOf(response.code());
        }

    }
    //在之前getPinningClient加了一次系统TM检测
    private static OkHttpClient getSecPinningClient() throws NoSuchAlgorithmException, KeyManagementException {
        final TrustManager[] pinningManager = new TrustManager[]{new MiPinningTrustManger(serverHostname)};
        // Install the  trust manager
        final SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, pinningManager, new java.security.SecureRandom());
        // Create an ssl socket factory with our  manager
        final javax.net.ssl.SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(sslSocketFactory);
        builder.hostnameVerifier(new SecHostNameVerifier());

        OkHttpClient okHttpClient = builder.build();
        return okHttpClient;
    }

}
