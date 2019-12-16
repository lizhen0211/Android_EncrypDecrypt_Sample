package com.lz.android_encrypdecrypt_sample;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.lz.android_encrypdecrypt_sample.AES.AESAgent;
import com.lz.android_encrypdecrypt_sample.RSA.RSAAgent;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        //testRSA();
        testAES();
    }

    public void testAES() {
        AESAgent aesAgent = new AESAgent();
        try {
            aesAgent.AESEncryptToBase64();
            aesAgent.AESEncryptToHexString();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    public void testRSA() {
        RSAAgent agent = new RSAAgent();
        try {
            //agent.RSAEncryptToHexStringByPrivateKey();
            //agent.RSAEncryptToBase64ByPrivateKey();
            agent.RSAEncryptToHexStringByPublicKey();
            agent.RSAEncryptToBase64ByPublicKey();
            //agent.RSASignToHexString();
            //agent.RSASignToBase64();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }


}
