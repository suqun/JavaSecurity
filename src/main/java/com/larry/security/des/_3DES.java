package com.larry.security.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Created by larry on 15-5-17.
 * 3DES对称加密算法使用
 * 密钥比DES更长，迭代次数更多
 */
public class _3DES {
    public static String src = "larry security 3des";

    public static void main(String[] args){
        jdk3DES();
        bc3DES();
    }

    /**
     * JDK提供的DES
     * 密钥长度(112,168)默认168
     */
    public static void jdk3DES(){
        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
//            keyGenerator.init(168);
            keyGenerator.init(new SecureRandom());//生成默认长度的key
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();
            //key转换
            DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            Key convertSecretKey = factory.generateSecret(desKeySpec);
            //加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("JDK 3DES encrypt : " + Hex.encodeHexString(result));
            //解密
            cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("JDK 3DES decrypt : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * BouncyCastle提供的3DES
     * 两种方式：provider/bc原生方法
     * 密钥长度必须是192或128
     */
    public static void bc3DES(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");//注意使用ＢＣ
//            keyGenerator.init(192);
            keyGenerator.init(new SecureRandom());//生成默认长度的key
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();
            //key转换
            DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
            Key convertSecretKey = factory.generateSecret(desKeySpec);
            //加密
            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("BC 3DES encrypt : " + Hex.encodeHexString(result));
            //解密
            cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("BC 3DES decrypt : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
