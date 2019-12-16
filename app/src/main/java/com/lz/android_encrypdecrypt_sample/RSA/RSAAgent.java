package com.lz.android_encrypdecrypt_sample.RSA;

import android.util.Base64;
import android.util.Log;

import com.lz.android_encrypdecrypt_sample.ByteUtil;
import com.lz.android_encrypdecrypt_sample.constants.Constants;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author lizhen
 */
public class RSAAgent {

    public static final String TAG = RSAAgent.class.getSimpleName();

    /**
     * RSA 签名得到 Base64
     *
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public void RSASignToBase64() throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        //生成密钥
        RSAPrivateKey privateKey = RSAUtil.genPrivateKeyFromStr(Constants.RSA_PRIVATEKEY);
        RSAPublicKey publicKey = RSAUtil.genPublicKeyFromStr(Constants.RSA_PUBLICKEY);
        //原始数据
        String originalData = "123456";
        //私钥签名 SHA1
        byte[] bytes = RSAUtil.signByPrivateKey(originalData, privateKey, RSAUtil.SIGN_SHA1RSA_ALGORITHM);
        // 字节数组 编码成 Base64字符串
        String base64String = Base64.encodeToString(bytes, Base64.DEFAULT);
        Log.e(TAG, "sign data encode by base64:" + base64String);
        //Base64字符串 解码成 字节数组
        byte[] decodeSignBytes = Base64.decode(base64String, Base64.DEFAULT);
        boolean verify = RSAUtil.verifyByPublicKey(originalData, decodeSignBytes, publicKey, RSAUtil.SIGN_SHA1RSA_ALGORITHM);
        Log.e(TAG, "verify result is " + verify);
    }

    /**
     * RSA 签名 得到 16进制
     *
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     */
    public void RSASignToHexString() throws InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        //生成密钥
        RSAPrivateKey privateKey = RSAUtil.genPrivateKeyFromStr(Constants.RSA_PRIVATEKEY);
        RSAPublicKey publicKey = RSAUtil.genPublicKeyFromStr(Constants.RSA_PUBLICKEY);
        //原始数据
        String originalData = "123456";
        //私钥签名 SHA1
        byte[] bytes = RSAUtil.signByPrivateKey(originalData, privateKey, RSAUtil.SIGN_SHA1RSA_ALGORITHM);
        // 字节数组 编码成 16进制字符串
        String hexString = ByteUtil.encodeHexString(bytes);
        Log.e(TAG, "sign data encode by hex:" + hexString);

        //16进制字符串 解码成 字节数组
        byte[] decodeSignBytes = ByteUtil.decodeHexString(hexString);
        boolean verify = RSAUtil.verifyByPublicKey(originalData, decodeSignBytes, publicKey, RSAUtil.SIGN_SHA1RSA_ALGORITHM);
        Log.e(TAG, "verify result is " + verify);
    }

    /**
     * 公钥加密 转 base64
     *
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     */
    public void RSAEncryptToBase64ByPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        //生成密钥
        RSAPrivateKey privateKey = RSAUtil.genPrivateKeyFromStr(Constants.RSA_PRIVATEKEY);
        RSAPublicKey publicKey = RSAUtil.genPublicKeyFromStr(Constants.RSA_PUBLICKEY);

        //原始数据
        String originalData = "123456";
        //============================= 加密 ========================================
        //公钥加密
        byte[] encryptBytes = RSAUtil.encryptByPublicKey(originalData, publicKey);
        // 字节数组 编码成 Base64字符串
        String base64String = Base64.encodeToString(encryptBytes, Base64.DEFAULT);
        Log.e(TAG, "encrypt data encode by base64:" + base64String);
        //============================== 解密 ====================================
        //Base64字符串 解码成 字节数组
        byte[] decodeEncryptBytes = Base64.decode(base64String, Base64.DEFAULT);
        //私钥解密
        byte[] decryptByBytes = RSAUtil.decryptByPrivateKey(decodeEncryptBytes, privateKey);
        Log.e(TAG, "decode data:" + new String(decryptByBytes));
    }

    /**
     * 公钥加密 转 16进制
     *
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     */
    public void RSAEncryptToHexStringByPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        //生成密钥
        RSAPrivateKey privateKey = RSAUtil.genPrivateKeyFromStr(Constants.RSA_PRIVATEKEY);
        RSAPublicKey publicKey = RSAUtil.genPublicKeyFromStr(Constants.RSA_PUBLICKEY);

        //原始数据
        String originalData = "123456";
        //============================= 加密 ========================================
        //公钥加密
        byte[] encryptBytes = RSAUtil.encryptByPublicKey(originalData, publicKey);
        // 字节数组 编码成 16进制字符串
        String hexString = ByteUtil.encodeHexString(encryptBytes);
        Log.e(TAG, "encrypt data encode by hex:" + hexString);
        //============================== 解密 ====================================
        //16进制字符串 解码成 字节数组
        byte[] decodeEncryptBytes = ByteUtil.decodeHexString(hexString);
        //私钥解密
        byte[] decryptByBytes = RSAUtil.decryptByPrivateKey(decodeEncryptBytes, privateKey);
        Log.e(TAG, "decode data:" + new String(decryptByBytes));
    }

    /**
     * 私钥加密转base64
     *
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     */
    public void RSAEncryptToBase64ByPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        //生成密钥
        RSAPrivateKey privateKey = RSAUtil.genPrivateKeyFromStr(Constants.RSA_PRIVATEKEY);
        RSAPublicKey publicKey = RSAUtil.genPublicKeyFromStr(Constants.RSA_PUBLICKEY);

        //原始数据
        String originalData = "123456";
        //============================= 加密 ========================================
        //私钥加密
        byte[] encryptBytes = RSAUtil.encryptByPrivateKey(originalData, privateKey);
        // 字节数组 编码成 Base64字符串
        String base64String = Base64.encodeToString(encryptBytes, Base64.DEFAULT);
        Log.e(TAG, "encrypt data encode by base64:" + base64String);
        //============================== 解密 ====================================
        //Base64字符串 解码成 字节数组
        byte[] decodeEncryptBytes = Base64.decode(base64String, Base64.DEFAULT);
        //公钥解密
        byte[] decryptByBytes = RSAUtil.decryptByPublicKey(decodeEncryptBytes, publicKey);
        Log.e(TAG, "decode data:" + new String(decryptByBytes));
    }

    /**
     * 私钥加密 转 16进制
     *
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     */
    public void RSAEncryptToHexStringByPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        //生成密钥
        RSAPrivateKey privateKey = RSAUtil.genPrivateKeyFromStr(Constants.RSA_PRIVATEKEY);
        RSAPublicKey publicKey = RSAUtil.genPublicKeyFromStr(Constants.RSA_PUBLICKEY);

        //原始数据
        String originalData = "123456";
        //============================= 加密 ========================================
        //私钥加密
        byte[] encryptBytes = RSAUtil.encryptByPrivateKey(originalData, privateKey);
        // 字节数组 编码成 16进制字符串
        String hexString = ByteUtil.encodeHexString(encryptBytes);
        Log.e(TAG, "encrypt data encode by hex:" + hexString);
        //============================== 解密 ====================================
        //16进制字符串 解码成 字节数组
        byte[] decodeEncryptBytes = ByteUtil.decodeHexString(hexString);
        //公钥解密
        byte[] decryptByBytes = RSAUtil.decryptByPublicKey(decodeEncryptBytes, publicKey);
        Log.e(TAG, "decode data:" + new String(decryptByBytes));
    }
}
