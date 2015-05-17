package com.larry.security.sha;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by larry on 15-5-17.
 * SHA实现 SHA1,SHA2(SHA-224,SHA-256,SHA-384,SHA-512)
 */
public class SHA {
    public static String src = "larry security md";

    public static void main(String[] args){
        jdkSHA1();
        bcSHA1();
        ccSHA1();
        bcSHA224();
        bcSHA224_2();
        ccSHA256();
    }

    /**
     * JDK的SHA1实现
     * 160为
     */
    public static void jdkSHA1(){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA");
            md.update(src.getBytes());
            byte[] shaBytes = md.digest();
            System.out.println("JDK SHA1 : " + Hex.encodeHexString(shaBytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * BouncyCastle的SHA1实现
     */
    public static void bcSHA1(){
        Digest digest = new SHA1Digest();
        digest.update(src.getBytes(),0,src.getBytes().length);
        byte[] sha1Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha1Bytes,0);
        System.out.println("BouncyCastle SHA1 : " +
                org.bouncycastle.util.encoders.Hex.toHexString(sha1Bytes));
    }

    /**
     * BouncyCastle的SHA224实现(JDK不提供224实现)
     * 224位
     */
    public static void bcSHA224(){
        Digest digest = new SHA224Digest();
        digest.update(src.getBytes(),0,src.getBytes().length);
        byte[] sha1Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(sha1Bytes,0);
        System.out.println("BouncyCastle SHA224 : " +
                org.bouncycastle.util.encoders.Hex.toHexString(sha1Bytes));
    }

    /**
     * BouncyCastle的SHA224实现
     * 通过设置Provider，使用MessageDigest实现SHA224
     * 224位
     */
    public static void bcSHA224_2(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest md = MessageDigest.getInstance("SHA224");
            md.update(src.getBytes());
            byte[] sha224Bytes = md.digest();
            System.out.println("BouncyCastle SHA224_2 : " +
                org.bouncycastle.util.encoders.Hex.toHexString(sha224Bytes));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * commonsCodec SHA1
     */
    public static void ccSHA1(){
        System.out.println("commonsCodec SHA1_1 : "
                + DigestUtils.sha1Hex(src.getBytes()));
        System.out.println("commonsCodec SHA1_2 : "
                + DigestUtils.sha1Hex(src));
    }

    /**
     * commonsCodec SHA256
     * 256位
     */
    public static void ccSHA256(){
        System.out.println("commonsCodec SHA256_1 : "
                + DigestUtils.sha256Hex(src.getBytes()));
        System.out.println("commonsCodec SHA256_2 : "
                + DigestUtils.sha256Hex(src));
    }
}
