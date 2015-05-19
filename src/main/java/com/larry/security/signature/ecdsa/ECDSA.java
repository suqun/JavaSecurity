package com.larry.security.signature.ecdsa;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by larry on 15-5-19.
 * ECDSA 数字签名
 * 速度快，强度高，签名短
 */
public class ECDSA {
    public static String src = "larry security ecdsa";

    public static void main(String[] args){
        jdkECDSA();
        bcECDSA();
    }

    /**
     * jdk的ECDSA签名
     *　NONEwithECDSA,SHA1WithECDSA,SHA256WithECDSA,
     *  SHA384WithECDSA,SHA512WithECDSA
     */
    public static void jdkECDSA(){
        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
            ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();
            System.out.println("public key : " + Base64.encodeBase64String(ecPublicKey.getEncoded()));
            System.out.println("private key : " + Base64.encodeBase64String(ecPrivateKey.getEncoded()));

            //2.执行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1WithECDSA");
            signature.initSign(privateKey);
            signature.update(src.getBytes());
            byte[] result = signature.sign();
            System.out.println("私钥签名，公钥验签--签名　: " + Base64.encodeBase64String(result));

            //3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("EC");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("SHA1WithECDSA");
            signature.initVerify(publicKey);
            signature.update(src.getBytes());
            Boolean bool = signature.verify(result);
            System.out.println("私钥签名，公钥验签--验签 : " + bool);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * BouncyCastle的DSA签名
     *  NONEwithECDSA,RIPEMD160withECDSA,SHA1WithECDSA,SHA224WithECDSA,SHA256WithECDSA,
     *  SHA384WithECDSA,SHA512WithECDSA
     *  默认密钥长度256
     */
    public static void bcECDSA(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC","BC");
            keyPairGenerator.initialize(256);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey)keyPair.getPublic();
            ECPrivateKey ecPrivateKey = (ECPrivateKey)keyPair.getPrivate();
            System.out.println("public key : " + Base64.encodeBase64String(ecPublicKey.getEncoded()));
            System.out.println("private key : " + Base64.encodeBase64String(ecPrivateKey.getEncoded()));

            //2.执行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("EC","BC");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1WithECDSA");
            signature.initSign(privateKey);
            signature.update(src.getBytes());
            byte[] result = signature.sign();
            System.out.println("私钥签名，公钥验签--签名　: " + Base64.encodeBase64String(result));

            //3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(ecPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("EC","BC");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("SHA1WithECDSA");
            signature.initVerify(publicKey);
            signature.update(src.getBytes());
            Boolean bool = signature.verify(result);
            System.out.println("私钥签名，公钥验签--验签 : " + bool);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
