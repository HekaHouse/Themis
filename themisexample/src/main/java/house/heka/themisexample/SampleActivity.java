package house.heka.themisexample;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.SecretKeySpec;

import house.heka.themis.Encrypt;
import house.heka.themis.EncryptedShare;
import house.heka.themis.LocalPref;

public class SampleActivity extends AppCompatActivity {

    private static final String TAG = "SampleActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(house.heka.themis.R.layout.activity_sample);
        Encrypt e = new Encrypt(this);

        Log.d(TAG, LocalPref.getStringPref(this,"publicECDH"));


        Log.d(TAG, LocalPref.getStringPref(this,"privateECDH"));

        try {
            SecretKeySpec shared = Encrypt.generateSharedSecret(
                    Encrypt.str2privateKey(LocalPref.getStringPref(this,"privateECDH")),
                    Encrypt.str2publicKey(LocalPref.getStringPref(this,"publicECDH"))
            );
            String str = "testy mctest";
            Log.d(TAG, str);
            EncryptedShare encrypted = Encrypt.encryptStringShared(str, shared, LocalPref.getStringPref(this,"publicECDH"));
            Log.d(TAG, encrypted.encryptedStr);
            String decrypted = Encrypt.decryptStringShared(encrypted, shared);
            Log.d(TAG, decrypted);
        } catch (GeneralSecurityException | IOException e1) {
            e1.printStackTrace();
        }


    }
}
