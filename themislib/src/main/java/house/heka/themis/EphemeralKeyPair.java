package house.heka.themis;

import android.content.Context;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.spec.SecretKeySpec;


public class EphemeralKeyPair {
    private final PublicKey pubKey;
    private final PrivateKey privKey;

    public EphemeralKeyPair(KeyPair kp, Context context) {
        pubKey = kp.getPublic();
        privKey = kp.getPrivate();
    }

    public PublicKey getPublic() {
        return pubKey;
    }

    public SecretKeySpec generateSharedSecret(PublicKey publicKey) throws GeneralSecurityException {
        return Encrypt.generateSharedSecret(privKey, publicKey);
    }
}
