package house.heka.themis;

import android.content.Context;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

/**
 * Stores a keypair and associated UUID
 */
public class EphemeralKeyPair {
    private String eid;
    private KeyPair ekeys;

    public EphemeralKeyPair(KeyPair kp, Context context) {
        ekeys = kp;
        eid = UUID.randomUUID().toString();
        try {
            LocalPref.putStringPref(context, "ephemeral_public:" + eid, Encrypt.publicKey2Str(kp.getPublic()));
            LocalPref.putStringPref(context, "ephemeral_private:" + eid, Encrypt.privateKey2Str(kp.getPrivate()));
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static PublicKey getPublic(Context context, String eid) throws GeneralSecurityException {
        String pub = LocalPref.getStringPref(context, "ephemeral_public:" + eid);
        if (pub != null)
            return Encrypt.str2publicKey(pub);
        return null;
    }

    public static SecretKeySpec generateSharedSecret(Context context, String eid, PublicKey publicKey) throws GeneralSecurityException {
        String priv_str = LocalPref.getStringPref(context, "ephemeral_private:" + eid);
        if (priv_str != null) {
            PrivateKey priv = Encrypt.str2privateKey(priv_str);
            return Encrypt.generateSharedSecret(priv, publicKey);
        }
        return null;
    }

    public String getEid() {
        return eid;
    }

    public PublicKey getPublic() {
        return ekeys.getPublic();
    }

    public SecretKeySpec generateSharedSecret(PublicKey publicKey) throws GeneralSecurityException {
        return Encrypt.generateSharedSecret(ekeys.getPrivate(), publicKey);
    }
}
