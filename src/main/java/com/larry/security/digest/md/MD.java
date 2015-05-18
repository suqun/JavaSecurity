package com.larry.security.digest.md;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by larry on 15-5-17.
 * MD摘要算法实现 jdk,bouncy castle,commons codec
 */
public class MD {
    public static String src = "larry security md";

    public static void main(String[] args){
        jdkMD5();
        bouncyCastleMD5();
        commonsCodecMD5();
        jdkMD2();
        commonsCodecMD2();
        bouncyCastleMD4();
        bouncyCastleMD4Two();
    }

    /**
     * JDK实现MD5
     * md.digest返回128位的字节数组，使用commonsCodec中提供的Hex类转成16进制字符串
     */
    public static void jdkMD5(){
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] md5Bytes = md.digest(src.getBytes());
            System.out.println("jdk md5 : " + Hex.encodeHexString(md5Bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * JDK实现MD2
     */
    public static void jdkMD2(){
        try {
            MessageDigest md = MessageDigest.getInstance("MD2");
            byte[] md5Bytes = md.digest(src.getBytes());
            System.out.println("jdk md2 : " + Hex.encodeHexString(md5Bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * bouncyCastle 重新实现算法
     */
    public static void bouncyCastleMD5(){
        Digest digest = new MD5Digest();
        digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] md4Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(md4Bytes,0);
        System.out.println("bouncyCastle md5 : " + org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes));

    }

    /**
     * JDK没有实现MD4算法，bouncyCastle实现MD4算法
     * 使用bouncyCastle中提供的Hex类转成16进制字符串
     */
    public static void bouncyCastleMD4(){
        Digest digest = new MD4Digest();
        digest.update(src.getBytes(), 0, src.getBytes().length);
        byte[] md4Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(md4Bytes,0);
        System.out.println("bouncyCastle md4 : " + org.bouncycastle.util.encoders.Hex.toHexString(md4Bytes));
    }

    /**
     * 通过设置Provider使用jdk的MessageDigest实现MD4方法
     */
    public static void bouncyCastleMD4Two(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            MessageDigest md = MessageDigest.getInstance("MD4");
            byte[] md5Bytes = md.digest(src.getBytes());
            System.out.println("bouncyCastle provider md4 : " + Hex.encodeHexString(md5Bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * CommonsCodec对jkd的Digest进行简化处理
     */
    public static void commonsCodecMD5(){
        System.out.println("commonsCodec md5 : " +DigestUtils.md5Hex(src.getBytes()));
    }

    public static void commonsCodecMD2(){
        System.out.println("commonsCodec md2 : " +DigestUtils.md2Hex(src.getBytes()));
    }
}
