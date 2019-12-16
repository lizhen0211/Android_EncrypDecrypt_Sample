package com.lz.android_encrypdecrypt_sample.RSA;

import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author lizhen
 */
public class RSAUtil {


    //================================== 加载密钥 开始 ==================================

    /**
     * 加密算法名称
     */
    public static final String RSA_ALGORITHM = "RSA";

    /**
     * 根据字符串生成公钥
     *
     * @param publicKeyStr 公钥字符串
     */
    public static RSAPublicKey genPublicKeyFromStr(String publicKeyStr)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] buffer = Base64.decode(publicKeyStr, Base64.DEFAULT);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 根据字符串生成私钥
     *
     * @param privateKeyStr 私钥字符串
     */
    public static RSAPrivateKey genPrivateKeyFromStr(String privateKeyStr)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] buffer = Base64.decode(privateKeyStr, Base64.DEFAULT);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    //================================== 加载密钥 结束 ==================================

    //================================== 加密解密数据 开始 ==================================

    /**
     * 加密填充方式
     */
    public static final String RSA_ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    /**
     * 公钥加密
     *
     * @param data      待加密数据
     * @param publicKey
     * @return 加密后的字节数组 （可转成Base64的字符串 或 16进制的字符串）
     */
    public static byte[] encryptByPublicKey(String data, RSAPublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cp = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        cp.init(Cipher.ENCRYPT_MODE, publicKey);
        return cp.doFinal(data.getBytes());
    }

    /**
     * 公钥解密
     *
     * @param data      待解密的数据
     * @param publicKey 公钥
     * @return 解密后的字节数组 （可转成Base64的字符串 或 16进制的字符串）
     */
    public static byte[] decryptByPublicKey(byte[] data, RSAPublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // 数据解密
        Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥加密
     *
     * @param data       待加密数据
     * @param privateKey
     * @return 加密后的字节数组 （可转成Base64的字符串 或 16进制的字符串）
     */
    public static byte[] encryptByPrivateKey(String data, RSAPrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data.getBytes());
    }

    /**
     * 私钥解密
     *
     * @param data       待解密的数据
     * @param privateKey 私钥
     * @return 解密后的字节数组 （可转成Base64的字符串 或 16进制的字符串）
     */
    public static byte[] decryptByPrivateKey(byte[] data, RSAPrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cp = Cipher.getInstance(RSA_ECB_PKCS1_PADDING);
        cp.init(Cipher.DECRYPT_MODE, privateKey);
        return cp.doFinal(data);
    }
    //================================== 加密解密数据 结束 ==================================

    //================================== 签名验签 开始 ==================================

    /**
     * 签名算法名称 RSA:SHA1
     * 对 RSA 密钥的长度不限制，推荐使用 2048 位以上
     */
    public static final String SIGN_SHA1RSA_ALGORITHM = "SHA1WithRSA";

    /**
     * 签名算法名称 RSA2:SHA256
     * 强制要求 RSA 密钥的长度至少为 2048
     */
    public static final String SIGN_SHA256RSA_ALGORITHM = "SHA256WithRSA";

    /**
     * 私钥签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @param algorithm  算法名称 SHA1WithRSA 或 SHA256WithRSA
     * @return 签名后的字节数组 （可转成Base64的字符串 或 16进制的字符串）
     */
    public static byte[] signByPrivateKey(String data, RSAPrivateKey privateKey, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = java.security.Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        byte[] signeData = signature.sign();
        return signeData;
    }

    /**
     * 公钥验签
     *
     * @param data      待验签数据
     * @param sign      签名数据 字节数组（可以是Base64转的字节数组，也可以是16进制转的字节数组）
     * @param publicKey 公钥
     * @param algorithm 算法名称 SHA1WithRSA 或 SHA256WithRSA
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyByPublicKey(String data, byte[] sign, RSAPublicKey publicKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        return signature.verify(sign);
    }

    //================================== 签名验签 结束 ==================================


}
