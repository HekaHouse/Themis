package house.heka.themis;

import android.content.Context;
import android.util.Log;

public class LocalPref {
    private static final String TAG = "LocalPref";
    private final static String prefsCollection = "themis-prefs";

    public static String getStringPref(Context c, String key) {
        boolean split = c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).getBoolean(key + ".split", false);
        if (split) {
            String dec = "";
            int chunks = c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).getInt(key + ".count", 1);
            for (int chunk = 0; chunk < chunks; chunk++) {
                String enc = c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).getString(key + "." + chunk, "");
                if (enc.length() > 0)
                    dec += Encrypt.decryptStringPrivate(enc);
            }
            return dec;
        } else {
            String enc = c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).getString(key, null);
            if (enc != null)
                return Encrypt.decryptStringPrivate(enc);
            else
                return null;
        }
    }

    public static void putStringPref(Context c, String key, String value) {
        String orig = value;
        String chunked = "";
        if (value.length() > 117) {
            c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putBoolean(key + ".split", true).apply();
            int count = value.length() / 117;
            if (value.length() % 117 > 0)
                count++;
            c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putInt(key + ".count", count).apply();
            int chunk = 0;
            while (value.length() > 117) {
                String nextChunk = value.substring(0, 116);
                c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putString(key + "." + chunk, Encrypt.encryptStringPrivate(nextChunk)).apply();
                chunked += nextChunk;
                value = value.substring(116);
                chunk++;
            }
            if (value.length() > 0) {
                c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putString(key + "." + chunk, Encrypt.encryptStringPrivate(value)).apply();
                chunked += value;
            }

        } else {
            chunked = value;
            c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putBoolean(key + ".split", false).apply();
            c.getSharedPreferences(prefsCollection, Context.MODE_PRIVATE).edit().putString(key, Encrypt.encryptStringPrivate(value)).apply();
        }
        if (!orig.equals(chunked)) {
            Log.d(TAG, orig);
            Log.d(TAG, chunked);
        } else {
            Log.d(TAG, "matches");
        }
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
