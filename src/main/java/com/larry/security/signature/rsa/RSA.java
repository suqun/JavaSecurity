package com.larry.security.signature.rsa;

import org.apache.commons.codec.binary.Base64;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by larry on 15-5-19.
 * RSA 签名算法　私钥签名，公钥验签
 */
public class RSA {
    public static String src = "larry security rsa";

    public static void main(String[] args){
        jdkRSA();
    }

    /**
     * jdk的RSA签名实现
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

            //2.执行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("MD5WithRSA");
            signature.initSign(privateKey);
            signature.update(src.getBytes());
            byte[] result = signature.sign();
            System.out.println("私钥签名，公钥验签--签名　: " + Base64.encodeBase64String(result));

            //3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("MD5WithRSA");
            signature.initVerify(publicKey);
            signature.update(src.getBytes());
            Boolean bool = signature.verify(result);
            System.out.println("私钥签名，公钥验签--验签 : " + bool);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
