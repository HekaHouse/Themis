package house.heka.themis;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;

public class LocalPref {
    private static final String TAG = "LocalPref";
    private final static String prefsCollection = "themis-prefs";

    public static String getStringPref(Context c, String key) {
        String enc = c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).getString(key, null);
        if (enc != null)
            return Encrypt.decryptStringPrivate(enc);
        else
            return null;
    }

    public static void putStringPref(Context c, String key, String value) {
        c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putString(key, Encrypt.encryptStringPrivate(value)).apply();
    }

    public static int getIntPref(Context c, String key) {

        int enc = c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).getInt(key, 0);
        if (enc != 0)
            return enc;
        else
            return 0;
    }

    public static void putIntPref(Context c, String key, int value) {

        c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putInt(key, value).apply();

    }
}
