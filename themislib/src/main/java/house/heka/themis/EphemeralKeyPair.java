package house.heka.themis;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Aron on 8/1/2016.
 */
public class EphemeralKeyPair {
    private String eid;
    private KeyPair ekeys;

    public EphemeralKeyPair(KeyPair kp) {
        ekeys = kp;
        eid = UUID.randomUUID().toString();
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
