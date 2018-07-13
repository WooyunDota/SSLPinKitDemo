package mi.ssl;

import android.util.Log;

import mi.sslpinningdemo.BuildConfig;

/**
 * Created by magic on 2018/3/29.
 */

public class LogUtil {
    public static final String TAG = "SecPin";
    public static void e(String s) {
        if (BuildConfig.DEBUG){
            Log.e(TAG,s);
        }
    }

    public static void i(String s) {

        if(BuildConfig.DEBUG){
            Log.i(TAG,s);
        }
    }
}
