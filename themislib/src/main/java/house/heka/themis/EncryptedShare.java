package house.heka.themis;

import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Created by Aron on 7/31/2016.
 */
public class EncryptedShare {
    public String iv;
    public String encryptedStr;
    public String publicKeyB64;

    public EncryptedShare(byte[] iv, String encryptedStr, String pubKey) {
        this.iv = Base64.encodeToString(iv, Base64.DEFAULT);
        this.encryptedStr = encryptedStr;
        this.publicKeyB64 = pubKey;
    }

    public JSONObject toJSON() throws JSONException {
        JSONObject json = new JSONObject();
        json.put("iv", iv);
        json.put("encrypted", encryptedStr);
        json.put("pubKey", publicKeyB64);
        return json;
    }
}
