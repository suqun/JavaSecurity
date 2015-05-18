package com.larry.security.asymmetry.rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by larry on 15-5-18.
 * RSA 非对称加密算法使用
 */
public class RSA {
    public static String src = "larry security dh";

    public static void main(String[] args){
        jdkRSA();
    }

    /**
     * jdk的RSA实现
     */
    public static void jdkRSA(){
        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
            System.out.println("public key : " + Base64.encodeBase64String(rsaPublicKey.getEncoded()));
            System.out.println("private key : " + Base64.encodeBase64String(rsaPrivateKey.getEncoded()));

            //2.私钥加密，公钥解密--加密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("私钥加密，公钥解密--加密 : " + Base64.encodeBase64String(result));

            //3.私钥加密，公钥解密--解密
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            result = cipher.doFinal(result);
            System.out.println("私钥加密，公钥解密--解密 : " + new String(result));

            //4.公钥加密，私钥解密--加密
            x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            result = cipher.doFinal(src.getBytes());
            System.out.println("公钥加密，私钥解密--加密　: " + Base64.encodeBase64String(result));

            //5.公钥加密，私钥解密--解密
            pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            result = cipher.doFinal(result);
            System.out.println("公钥加密，私钥解密--解密 : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
