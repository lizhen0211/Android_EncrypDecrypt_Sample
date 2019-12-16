package com.lz.android_encrypdecrypt_sample.AES;

import java.security.GeneralSecurityException;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

    /**
     * 加解密算法/模式/填充方式
     */
    public static final String AES_CBC_PKCS7PADDING = "AES/CBC/PKCS7Padding";

    /**
     * More flexible AES encrypt that doesn't encode
     *
     * @param key     AES key typically 128, 192 or 256 bit
     * @param iv      Initiation Vector
     * @param message in bytes (assumed it's already been decoded)
     * @return Encrypted cipher text (not encoded)
     * @throws GeneralSecurityException if something goes wrong during encryption
     */
    public static byte[] encrypt(final SecretKeySpec key, final byte[] iv, final byte[] message)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(AES_CBC_PKCS7PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = cipher.doFinal(message);
        return cipherText;
    }

    /**
     * More flexible AES decrypt that doesn't encode
     *
     * @param key               AES key typically 128, 192 or 256 bit
     * @param iv                Initiation Vector
     * @param decodedCipherText in bytes (assumed it's already been decoded)
     * @return Decrypted message cipher text (not encoded)
     * @throws GeneralSecurityException if something goes wrong during encryption
     */
    public static byte[] decrypt(final SecretKeySpec key, final byte[] iv, final byte[] decodedCipherText)
            throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(AES_CBC_PKCS7PADDING);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(decodedCipherText);
        return decryptedBytes;
    }

    // 算法名称
    public static final String ALGORITHM = "AES";

    /**
     * 生成AES随机密钥
     *
     * @return
     */
    public static SecretKeySpec generateRandomAESKey() {
        UUID uuid = UUID.randomUUID();
        String uuidStr = uuid.toString().replace("-", "");
        return new SecretKeySpec(uuidStr.getBytes(), ALGORITHM);
    }
}
