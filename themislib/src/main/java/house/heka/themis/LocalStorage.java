package house.heka.themis;

import android.os.Environment;
import android.util.Log;

import java.io.File;

public class LocalStorage {

    private static final String TAG = "LocalStorage";

    public static File getExternalStorage(String appName) {
        String path = "/heka.house/"+appName+"/";
        File dir = new File(Environment.getExternalStorageDirectory() + path);
        if (!dir.exists()) {
            boolean success = dir.mkdirs();
            if (!success) {
                Log.e(TAG, "mkdirs failed");
            }
        }
        return dir;
    }
}
