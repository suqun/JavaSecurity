package com.larry.security.digest.base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

/**
 * Created by larry on 15-5-17.
 * Base64 实现
 */
public class Base64 {

    public static String src = "larry security base64";

    public static void main(String[] args){
        jdkBase64();
        commonsCodecBase64();
        bouncyCastleBase64();
    }

    //jdk提供的不建议使用
    public static void jdkBase64(){
        try {
            BASE64Encoder encoder = new BASE64Encoder();
            String encode = encoder.encode(src.getBytes());
            System.out.println("jdk encode : " + encode);

            BASE64Decoder decoder = new BASE64Decoder();
            System.out.println("jdk decode : " + new String(decoder.decodeBuffer(encode)));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void commonsCodecBase64(){
        byte[] encodeBytes = org.apache.commons.codec.binary.Base64.encodeBase64(src.getBytes());
        System.out.println("commonsCodec encode : " + new String(encodeBytes));

        byte[] decodeBytes = org.apache.commons.codec.binary.Base64.decodeBase64(encodeBytes);
        System.out.println("commonsCodec decode : " + new String(decodeBytes));
    }

    public static void bouncyCastleBase64(){
        byte[] encodeBytes =  org.bouncycastle.util.encoders.Base64.encode(src.getBytes());
        System.out.println("bouncyCastle encode : " + new String(encodeBytes));

        byte[] decodeBytes =  org.bouncycastle.util.encoders.Base64.decode(encodeBytes);
        System.out.println("bouncyCastle decode : " + new String(decodeBytes));
    }

}
