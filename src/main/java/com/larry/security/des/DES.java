package com.larry.security.des;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * Created by larry on 15-5-17.
 * DES对称加密算法使用
 * 密钥长度56,不安全
 */
public class DES {
    public static String src = "larry security des";

    public static void main(String[] args){
        jdkDES();
        bcDES();
    }

    /**
     * JDK提供的DES
     */
    public static void jdkDES(){
        try {
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
            keyGenerator.init(56);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();
            //key转换
            DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            Key convertSecretKey = factory.generateSecret(desKeySpec);
            //加密
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("JDK DES encrypt : " + Hex.encodeHexString(result));
            //解密
            cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("JDK DES decrypt : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * BouncyCastle提供的DES
     * 两种方式：provider/bc原生方法
     */
    public static void bcDES(){
        try {
            Security.addProvider(new BouncyCastleProvider());
            //生成key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");//注意使用ＢＣ
            keyGenerator.init(56);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] bytesKey = secretKey.getEncoded();
            //key转换
            DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
            Key convertSecretKey = factory.generateSecret(desKeySpec);
            //加密
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("BC DES encrypt : " + Hex.encodeHexString(result));
            //解密
            cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
            result = cipher.doFinal(result);
            System.out.println("BC DES decrypt : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
