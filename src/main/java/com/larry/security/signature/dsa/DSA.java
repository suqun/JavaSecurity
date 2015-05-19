package com.larry.security.signature.dsa;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.provider.DSAPrivateKey;
import sun.security.provider.DSAPublicKey;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by larry on 15-5-19.
 * DSA 数字签名
 */
public class DSA {
    public static String src = "larry security dsa";

    public static void main(String[] args){
        jdkDSA();
        bcDSA();
    }

    /**
     * jdk的DSA签名
     * jdk只提供SHA1WithDSA，其他sha224等都是bouncy castle 提供
     */
    public static void jdkDSA(){
        try {
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            DSAPublicKey dsaPublicKey = (DSAPublicKey)keyPair.getPublic();
            DSAPrivateKey dsaPrivateKey = (DSAPrivateKey)keyPair.getPrivate();
            System.out.println("public key : " + Base64.encodeBase64String(dsaPublicKey.getEncoded()));
            System.out.println("private key : " + Base64.encodeBase64String(dsaPrivateKey.getEncoded()));

            //2.执行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(dsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("DSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA1WithDSA");
            signature.initSign(privateKey);
            signature.update(src.getBytes());
            byte[] result = signature.sign();
            System.out.println("私钥签名，公钥验签--签名　: " + Base64.encodeBase64String(result));

            //3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(dsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("DSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("SHA1WithDSA");
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
     * 其他SHA224WithDSA,SHA256WithDSA,SHA384WithDSA,SHA512WithDSA都是bouncy castle 提供
     */
    public static void bcDSA(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            //1.初始化密钥
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA","BC");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            BCDSAPublicKey dsaPublicKey = (BCDSAPublicKey)keyPair.getPublic();
            BCDSAPrivateKey dsaPrivateKey = (BCDSAPrivateKey)keyPair.getPrivate();
            System.out.println("public key : " + Base64.encodeBase64String(dsaPublicKey.getEncoded()));
            System.out.println("private key : " + Base64.encodeBase64String(dsaPrivateKey.getEncoded()));

            //2.执行签名
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(dsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("DSA","BC");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Signature signature = Signature.getInstance("SHA224WithDSA");
            signature.initSign(privateKey);
            signature.update(src.getBytes());
            byte[] result = signature.sign();
            System.out.println("私钥签名，公钥验签--签名　: " + Base64.encodeBase64String(result));

            //3.验证签名
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(dsaPublicKey.getEncoded());
            keyFactory = KeyFactory.getInstance("DSA","BC");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("SHA224WithDSA");
            signature.initVerify(publicKey);
            signature.update(src.getBytes());
            Boolean bool = signature.verify(result);
            System.out.println("私钥签名，公钥验签--验签 : " + bool);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
