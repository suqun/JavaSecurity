package com.larry.security.symmetry.aes;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Created by larry on 15-5-17.
 * AES对称加密算法使用
 * 效率比3DES高，至今未被破解，使用最多的对称加密算法,DES的替代者
 * 密钥长度128,192,256 默认128
 */
public class AES {
    public static String src = "larry security aes";

    public static void main(String[] args){
        jdkAES();
        bcAES();
    }

    public static void jdkAES(){
        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            //keyGenerator.init(128);
            keyGenerator.init(new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();

            //key的转换
            Key key = new SecretKeySpec(keyBytes,"AES");

            //加密
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//加解密方式／工作模式／填充模式
            cipher.init(Cipher.ENCRYPT_MODE,key);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("JDK AES encrypt : " + Hex.encodeHexString(result));

            //解密
            cipher.init(Cipher.DECRYPT_MODE,key);
            result = cipher.doFinal(result);
            System.out.println("JDK AES decrypt : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * BouncyCastle提供的AES
     * 两种方式：provider/bc原生方法
     */
    public static void bcAES(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");//注意使用ＢＣ
            keyGenerator.init(128);
//            keyGenerator.init(new SecureRandom());//bcAES使用这个是抛出异常Illegal key size or default parameters
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] keyBytes = secretKey.getEncoded();

            //key的转换
            Key key = new SecretKeySpec(keyBytes,"AES");

            //加密
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");//加解密方式／工作模式／填充模式
            cipher.init(Cipher.ENCRYPT_MODE,key);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("BC AES encrypt : " + Hex.encodeHexString(result));

            //解密
            cipher.init(Cipher.DECRYPT_MODE,key);
            result = cipher.doFinal(result);
            System.out.println("BC AES encrypt : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
