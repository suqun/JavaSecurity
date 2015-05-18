package com.larry.security.asymmetry.ElGamal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by larry on 15-5-18.
 * EIGamal 非对称公钥加密算法　Bouncy Castle实现
 */
public class ElGamal {
    public static String src = "larry security ElGamal";

    public static void main(String[] args){
        bcElGamal();
    }

    /**
     * bouncy castle实现的ElGamal算法使用
     */
    public static void bcElGamal(){
        try {
            //公钥加密，私钥解密
            Security.addProvider(new BouncyCastleProvider());

            //1.初始化密钥
            AlgorithmParameterGenerator algorithmParameterGenerator =
                    AlgorithmParameterGenerator.getInstance("ElGamal");
            algorithmParameterGenerator.init(256);
            AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();
            DHParameterSpec dhParameterSpec = (DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
            keyPairGenerator.initialize(dhParameterSpec,new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey elGamalPublicKey = keyPair.getPublic();
            PrivateKey elGamalPrivateKey = keyPair.getPrivate();
            System.out.println("public key : " + Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
            System.out.println("private key : " + Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));

            //4.公钥加密，私钥解密--加密
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("公钥加密，私钥解密--加密　: " + Base64.encodeBase64String(result));

            //5.公钥加密，私钥解密--解密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
            keyFactory = KeyFactory.getInstance("ElGamal");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            result = cipher.doFinal(result);
            System.out.println("公钥加密，私钥解密--解密 : " + new String(result));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 运行结果：
     * /usr/lib/jvm/jdk1.8.0_45/bin/java -Didea.launcher.port=7534 -Didea.launcher.bin.path=/opt/idea-IU-141.713.2/bin -Dfile.encoding=UTF-8 -classpath /usr/lib/jvm/jdk1.8.0_45/jre/lib/plugin.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/management-agent.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/javaws.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/jce.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/resources.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/deploy.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/jfr.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/rt.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/charsets.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/jsse.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/jfxswt.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/sunpkcs11.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/sunec.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/zipfs.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/sunjce_provider.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/dnsns.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/cldrdata.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/jfxrt.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/localedata.jar:/usr/lib/jvm/jdk1.8.0_45/jre/lib/ext/nashorn.jar:/home/larry/Projects/IdeaProjects/JavaSecurity/target/classes:/home/larry/.m2/repository/org/bouncycastle/bcprov-jdk15on/1.52/bcprov-jdk15on-1.52.jar:/home/larry/.m2/repository/org/apache/directory/studio/org.apache.commons.codec/1.8/org.apache.commons.codec-1.8.jar:/home/larry/.m2/repository/commons-codec/commons-codec/1.8/commons-codec-1.8.jar:/opt/idea-IU-141.713.2/lib/idea_rt.jar com.intellij.rt.execution.application.AppMain com.larry.security.asymmetry.ElGamal.ElGamal
     public key : MHYwTwYGKw4HAgEBMEUCIQDuDEPAafaof59S7jo0mACzpK8UJZAEvAAkTMUf+yN9XwIgUIwRuAv7qVooRjEtQILL3R1ruOyPmFzK8WcUOpLjluADIwACIHUrV8yGIj3shFT5yYhP8d/AcWa/uBDDiJ+wZ1l8hCRL
     private key : MHkCAQAwTwYGKw4HAgEBMEUCIQDuDEPAafaof59S7jo0mACzpK8UJZAEvAAkTMUf+yN9XwIgUIwRuAv7qVooRjEtQILL3R1ruOyPmFzK8WcUOpLjluAEIwIhALYTbsrTcFST0bDq1roM/RW20RjGqhkU/Lpv2JOOY5Zp
     java.security.InvalidKeyException: Illegal key size or default parameters
     at javax.crypto.Cipher.checkCryptoPerm(Cipher.java:1026)
     at javax.crypto.Cipher.implInit(Cipher.java:801)
     at javax.crypto.Cipher.chooseProvider(Cipher.java:864)
     at javax.crypto.Cipher.init(Cipher.java:1249)
     at javax.crypto.Cipher.init(Cipher.java:1186)
     at com.larry.security.asymmetry.ElGamal.ElGamal.bcElGamal(ElGamal.java:50)
     at com.larry.security.asymmetry.ElGamal.ElGamal.main(ElGamal.java:20)
     at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
     at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
     at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
     at java.lang.reflect.Method.invoke(Method.java:497)
     at com.intellij.rt.execution.application.AppMain.main(AppMain.java:140)

     Process finished with exit code 0

     * 出现上述现象是因为美国的出口管制限制，Java发布的运行环境包中的加解密有一定的限制。比如默认不允许256位密钥的AES加解密，解决方法就是修改策略文件。
     官方网站提供了JCE无限制权限策略文件的下载：
     JDK8的下载地址：

     JDK7的下载地址：

     下载后解压，可以看到local_policy.jar和US_export_policy.jar以及readme.txt。
     将两个jar文件放到%JRE_HOME%\lib\security下覆盖原来文件。

     将两个jar文件也放到%JDK_HOME%\jre\lib\security下。

     如果是使用MyEclpse等工具编写java文件，则需要将MyEclipse的JRE编译环境换位本地安装目录的JRE.

     或者直接将\MyEclipse Professional 2014\binary\com.sun.java.jdk7.win32.x86_64_1.7.0.u45\jre\lib\security目录下的文件覆盖，就可以编译通过。
     */
}
