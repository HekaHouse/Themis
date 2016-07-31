package house.heka.themis;

/**
 * Created by Aron on 7/31/2016.
 */
public class EncryptedShare {
    public byte[] iv;
    public String encryptedStr;
    public String publicKeyB64;

    public EncryptedShare(byte[] iv, String encryptedStr, String pubKey) {
        this.iv = iv;
        this.encryptedStr = encryptedStr;
        this.publicKeyB64 = pubKey;
    }
}
