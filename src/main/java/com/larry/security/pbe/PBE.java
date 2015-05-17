package com.larry.security.pbe;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.SecureRandom;

/**
 * Created by larry on 15-5-17.
 * PBE对称加密算法(Password Based Encryption) 基于口令加密
 * 结合了消息摘要算法和对称加密算法的优点
 * 对已有的算法（DES,AES等）的包装
 */
public class PBE {
    public static String src = "larry security pbe";

    public static void main(String[] args){
        jdkPBE();
    }

    public static void jdkPBE(){
        try {
            //初始化盐
            SecureRandom random = new SecureRandom();
            byte[] salt = random.generateSeed(8);

            //口令与密钥
            String password = "larry";//密码
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            Key key = factory.generateSecret(pbeKeySpec);

            //加密
            PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt,100);//盐，迭代次数
            Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
            cipher.init(Cipher.ENCRYPT_MODE,key,pbeParameterSpec);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("JDK PBE encrypt : " + Hex.encodeHexString(result));

            //解密
            cipher.init(Cipher.DECRYPT_MODE,key,pbeParameterSpec);
            result = cipher.doFinal(result);
            System.out.println("JDK PBE decrypt : " + new String(result));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
