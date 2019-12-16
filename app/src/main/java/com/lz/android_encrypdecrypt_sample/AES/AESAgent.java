package com.lz.android_encrypdecrypt_sample.AES;

import android.util.Base64;
import android.util.Log;

import com.lz.android_encrypdecrypt_sample.ByteUtil;

import java.security.GeneralSecurityException;

import javax.crypto.spec.SecretKeySpec;

public class AESAgent {

    public static final String TAG = AESAgent.class.getSimpleName();


    /**
     * AES加密 转 Base64
     *
     * @return
     * @throws GeneralSecurityException
     */
    public void AESEncryptToBase64() throws GeneralSecurityException {
        SecretKeySpec secretKeySpec = AESUtil.generateRandomAESKey();
        byte[] ivBytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        //原始数据
        String originalData = "123456";
        byte[] encryptBytes = AESUtil.encrypt(secretKeySpec, ivBytes, originalData.getBytes());
        String encryptMsg = Base64.encodeToString(encryptBytes, Base64.DEFAULT);
        Log.e(TAG, "encrypt data encode by base64:" + encryptMsg);

        byte[] decryptBytes = Base64.decode(encryptMsg.getBytes(), Base64.DEFAULT);
        byte[] decrypt = AESUtil.decrypt(secretKeySpec, ivBytes, decryptBytes);
        Log.e(TAG, "decode data:" + new String(decrypt));
    }


    /**
     * AES加密 转 十六进制
     *
     * @return
     * @throws GeneralSecurityException
     */
    public void AESEncryptToHexString() throws GeneralSecurityException {
        SecretKeySpec secretKeySpec = AESUtil.generateRandomAESKey();
        byte[] ivBytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        //原始数据
        String originalData = "123456";
        byte[] encryptBytes = AESUtil.encrypt(secretKeySpec, ivBytes, originalData.getBytes());
        String encryptMsg = ByteUtil.encodeHexString(encryptBytes);
        Log.e(TAG, "encrypt data encode by hexString:" + encryptMsg);

        byte[] decryptBytes = ByteUtil.decodeHexString(encryptMsg);
        byte[] decrypt = AESUtil.decrypt(secretKeySpec, ivBytes, decryptBytes);
        Log.e(TAG, "decode data:" + new String(decrypt));
    }
}
