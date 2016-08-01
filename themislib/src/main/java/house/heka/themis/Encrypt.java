package house.heka.themis;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;


public class Encrypt {
    private static final String TAG = "Encrypt";
    private static String alias = "Encrypt-Key";

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public Encrypt(Context context) {
        try {
            generateECDH(context);
        } catch (IOException | GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public static SecretKeySpec generateSharedSecret(PrivateKey privateKey,
                                              PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "SC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true); // public key is from external source
        return new SecretKeySpec(keyAgreement.generateSecret(), "AES");
    }

    public static KeyPair generateEphemeralKeys() throws GeneralSecurityException {
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("brainpoolp256t1");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "SC");

        kpg.initialize(ecParamSpec, new SecureRandom());
        return kpg.generateKeyPair();
    }


    public static EncryptedShare encryptStringShared(String toEncrypt, SecretKeySpec secretKey, String pubKey) throws GeneralSecurityException {

        SecureRandom random = new SecureRandom();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] realIV = new byte[cipher.getBlockSize()];
        random.nextBytes(realIV);
        IvParameterSpec ivSpec = new IvParameterSpec(realIV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        byte[] dataToEncrypt = toEncrypt.getBytes(Charset.forName("UTF-8"));

        byte[] encryptedData = cipher.doFinal(dataToEncrypt);

        return new EncryptedShare(realIV, Base64.encodeToString(encryptedData, Base64.DEFAULT), pubKey);
    }

    public static String decryptStringShared(EncryptedShare encrypted, SecretKeySpec secretKey) throws GeneralSecurityException, IOException {

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(Base64.decode(encrypted.iv, Base64.DEFAULT));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        CipherInputStream cipherInputStream = new CipherInputStream(
                new ByteArrayInputStream(Base64.decode(encrypted.encryptedStr, Base64.DEFAULT)), cipher);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }
        byte[] bytes = new byte[values.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i);
        }
        return new String(Base64.decode(Base64.encode(bytes, Base64.DEFAULT), Base64.DEFAULT));
    }

    public static String encryptStringPrivate(String toEncrypt) {
        String encryptedText = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
            Cipher c = Cipher.getInstance("RSA/NONE/OAEPwithSHA-256andMGF1Padding");
            c.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedText = Base64.encodeToString(c.doFinal(toEncrypt.getBytes()), Base64.DEFAULT);
        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return encryptedText;
    }

    public static String decryptStringPrivate(String encrypted) {
        String decrypted = null;
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);

            Cipher output = Cipher.getInstance("RSA/NONE/OAEPwithSHA-256andMGF1Padding");
            output.init(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(encrypted, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte) nextByte);
            }
            byte[] bytes = new byte[values.size()];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }
            decrypted = new String(Base64.decode(Base64.encode(bytes, Base64.DEFAULT), Base64.DEFAULT));


        } catch (Exception e) {
            Log.e(TAG, Log.getStackTraceString(e));
        }

        return decrypted;
    }

    public static String privateKey2Str(PrivateKey priv) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec spec = fact.getKeySpec(priv,
                PKCS8EncodedKeySpec.class);
        byte[] packed = spec.getEncoded();
        return Base64.encodeToString(packed, Base64.DEFAULT);
    }

    public static String publicKey2Str(PublicKey publ) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("EC");
        X509EncodedKeySpec spec = fact.getKeySpec(publ,
                X509EncodedKeySpec.class);
        return Base64.encodeToString(spec.getEncoded(), Base64.DEFAULT);
    }

    public static PrivateKey str2privateKey(String priv_enc) throws GeneralSecurityException {
        byte[] keyBytes = Base64.decode(priv_enc, Base64.DEFAULT);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        KeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static PublicKey str2publicKey(String publ_enc) throws GeneralSecurityException {
        byte[] keyBytes = Base64.decode(publ_enc, Base64.DEFAULT);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    private void generateECDH(Context context) throws GeneralSecurityException, IOException {
        createEncryptionKeyStore(context);

        if (LocalPref.getStringPref(context, "publicECDH") == null) {
            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("brainpoolp256t1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "SC");

            kpg.initialize(ecParamSpec, new SecureRandom());
            KeyPair kpair = kpg.generateKeyPair();
            PublicKey pkey = kpair.getPublic();
            PrivateKey skey = kpair.getPrivate();

            String pub = publicKey2Str(pkey);
            LocalPref.putStringPref(context, "publicECDH", pub);

            String priv = privateKey2Str(skey);
            LocalPref.putStringPref(context, "privateECDH", priv);

        }
    }

    private void createEncryptionKeyStore(Context context) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String exists = aliases.nextElement();
            if (exists.equals(alias))
                return;
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                "RSA", "AndroidKeyStore");

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 25);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .build());
            keyPairGenerator.generateKeyPair();
        } else {
            KeyPairGenerator kpg;
            kpg = KeyPairGenerator.getInstance(
                    "RSA", "AndroidKeyStore");
            KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(alias)
                    .setSubject(new X500Principal("CN=Themis, O=Heka House"))
                    .setSerialNumber(BigInteger.ONE)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
            kpg.initialize(spec);

            kpg.generateKeyPair();
        }
    }
}
