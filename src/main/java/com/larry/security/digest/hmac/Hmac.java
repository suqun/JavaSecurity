package com.larry.security.digest.hmac;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by larry on 15-5-17.
 * MAC 算法实现使用
 */
public class Hmac {
    public static String src = "larry security md";

    public static void main(String[] args){
        jdkHmacMD5();
        bcHmacMD5();
    }

    /**
     * jdk的Hmac MD5方法
     */
    public static void jdkHmacMD5(){
        try {
            //初始化keyGenerator
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
            //产生密钥
            SecretKey secretKey = keyGenerator.generateKey();
            //获得密钥
//            byte[] key = secretKey.getEncoded();//自动生成的key
            byte[] key = Hex.decodeHex(new char[]{'a','a','a','a','a','a','a','a','a','a'});//手动设置key

            //还原密钥
            SecretKey restoreSecretKey = new SecretKeySpec(key,"HmacMD5");
            //实例化MAC
            Mac mac = Mac.getInstance(restoreSecretKey.getAlgorithm());
            //初始化Mac
            mac.init(restoreSecretKey);
            //执行摘要
            byte[] hmacMD5Bytes = mac.doFinal(src.getBytes());

            System.out.println("JDK HmacMD5 : " + Hex.encodeHexString(hmacMD5Bytes));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (DecoderException e) {
            e.printStackTrace();
        }
    }

    /**
     * BouncyCastle的HmacMD5
     */
    public static void bcHmacMD5(){
        HMac hmac = new HMac(new MD5Digest());
        hmac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("aaaaaaaaaa")));
        hmac.update(src.getBytes(),0,src.getBytes().length);

        byte[] hmacMD5Bytes = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacMD5Bytes,0);
        System.out.println("BouncyCastle HmacMD5 : " + org.bouncycastle.util.encoders.Hex.toHexString(hmacMD5Bytes));
    }
}
