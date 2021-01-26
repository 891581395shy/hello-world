package org.songhaiyan.learning.cryptography;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;

/**
 * @ClassName: RSAUtils.java
 * @Description: Java RSA 加密工具类
 * @Author: 宋海燕(songhaiyan @ bjca.org.cn)
 * @Date: 2021/1/26 10:13
 * @Version: V2.0.1
 **/
public class RSAUtils {

  /**
   * 密钥长度(模长，二进制) 与原文长度对应，越长速度越慢
   */
  private final static int KEY_SIZE = 1024;
  private final static String algorithm = "SHA256withRSA";

  //用于封装随机产生的公钥与私钥
  private static Map<Integer, String> keyMap = new HashMap<>();

  @Test
  public void testCrypto() throws Exception {
    long temp = System.currentTimeMillis();
    //生成公钥和私钥
    genKeyPair();
    System.out.println("公钥:" + keyMap.get(0));
    System.out.println("私钥:" + keyMap.get(1));
    System.out.println("生成密钥消耗时间:" + (System.currentTimeMillis() - temp) / 1000.0 + "秒");
    //加密字符串
    String message = "RSA测试ABCD~!@#$";
    System.out.println("原文:" + message);
    temp = System.currentTimeMillis();
    String messageEn = encrypt(message, keyMap.get(0));
    System.out.println("密文:" + messageEn);
    System.out.println("加密消耗时间:" + (System.currentTimeMillis() - temp) / 1000.0 + "秒");
    temp = System.currentTimeMillis();
    String messageDe = decrypt(messageEn, keyMap.get(1));
    System.out.println("解密:" + messageDe);
    System.out.println("解密消耗时间:" + (System.currentTimeMillis() - temp) / 1000.0 + "秒");
    System.out.println("--------------------------------------------------");


  }
  @Test
  public void testSignAndVerify() throws Exception {
    //生成公钥和私钥
    genKeyPair();
    //加密字符串
    String message = "RSA测试ABCD~!@#$";
    String sign = sign(message, keyMap.get(1));
    System.out.println("sign:" + sign);
    boolean result = verify(message, keyMap.get(0), sign);
    System.out.println( "verify result: " + result);
  }

  @Test
  public void testSaveKeyPair() throws Exception {
    final String algorithm = "RSA";
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);

    keyPairGenerator.initialize(1024);

    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    //公钥（e,N）, 私钥（d,N）
    /*特征值N  e   d*/
    BigInteger N = publicKey.getModulus();
    BigInteger e = publicKey.getPublicExponent();
    BigInteger d = privateKey.getPrivateExponent();
    BigInteger Npri = privateKey.getModulus();

    /**/
    String nStr = Base64.getEncoder().encodeToString(N.toByteArray());
    String eStr = Base64.getEncoder().encodeToString(e.toByteArray());
    String dStr = Base64.getEncoder().encodeToString(d.toByteArray());
    String nStrPri = Base64.getEncoder().encodeToString(Npri.toByteArray());
    System.out.println("nStr:" + nStr);
    System.out.println("eStr:" + eStr);
    System.out.println("dStr:" + dStr);
    System.out.println("nStrPri:" + nStrPri);
    System.out.println(nStrPri.endsWith(nStr));
    /*将这三个字符串保存到文件或者数据库，通常n，e可以保存在客户端，而n，d的数据必须保存在服务端*/


    N = new BigInteger(Base64.getDecoder().decode(nStr));
    e = new BigInteger(Base64.getDecoder().decode(eStr));
    d = new BigInteger(Base64.getDecoder().decode(dStr));
    System.out.println("N:" + N);
    System.out.println("e:" + e);
    System.out.println("d:" + d);

    /*根据N，e生成公钥*/
    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(N, e);
    PublicKey pbk = KeyFactory.getInstance(algorithm).generatePublic(publicKeySpec);

    Cipher cipher = Cipher.getInstance(algorithm);
    cipher.init(Cipher.ENCRYPT_MODE, pbk);
    //bytes 是加密后的数据
    byte[] bytes = cipher.doFinal("helloworld".getBytes());
    //用base64转换输出
    System.out.println("加密数据：" + Base64.getUrlEncoder().encodeToString(bytes));

    /*根据N，d生成私钥*/
    RSAPrivateKeySpec ps = new RSAPrivateKeySpec(N, d);
    PrivateKey prk = KeyFactory.getInstance(algorithm).generatePrivate(ps);

    cipher.init(Cipher.DECRYPT_MODE, prk);
    bytes = cipher.doFinal(bytes);
    System.out.println("解密数据：" + new String(bytes));
  }



  /**
   * @Description: 随机生成密钥对
   * @return: void
   * @author: 宋海燕(songhaiyan @ bjca.org.cn)
   * @date: 2021/1/26 11:55
   */
  public static void genKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
    // 初始化密钥对生成器，密钥大小为96-1024位  
    keyPairGen.initialize(KEY_SIZE, new SecureRandom());
    // 生成一个密钥对，保存在keyPair中
    KeyPair keyPair = keyPairGen.generateKeyPair();
    // 得到私钥
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    // 得到公钥
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    // 得到私钥字符串
    String privateKeyStr = Base64.getEncoder().encodeToString(privateKey.getEncoded());
    // 得到公钥字符串
    String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    // 将公钥和私钥保存到Map
    //0表示公钥
    keyMap.put(0, publicKeyStr);
    //1表示私钥
    keyMap.put(1, privateKeyStr);
  }

  /**
   * @Description: RSA公钥加密
   * @param: plainData 明文
   * @param: publicKey base64的公钥
   * @return: java.lang.String base64的密文
   * @author: 宋海燕(songhaiyan @ bjca.org.cn)
   * @date: 2021/1/26 11:51
   */
  public static String encrypt(String plainData, String publicKey) throws Exception {
    //base64编码的公钥
    byte[] decoded = Base64.getDecoder().decode(publicKey);
    RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    //RSA加密
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);

    return Base64.getEncoder().encodeToString(cipher.doFinal(plainData.getBytes("UTF-8")));
  }

  /**
   * @Description: RSA私钥解密
   * @param: cipherText base64的密文
   * @param: privateKey base64的私钥
   * @return: java.lang.String 明文
   * @author: 宋海燕(songhaiyan @ bjca.org.cn)
   * @date: 2021/1/26 12:25
   */
  public static String decrypt(String cipherText, String privateKey) throws Exception {
    //解base64后的密文
    byte[] inputByte = Base64.getDecoder().decode(cipherText);
    //私钥
    byte[] decoded = Base64.getDecoder().decode(privateKey);
    RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
    //RSA解密
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, priKey);
    String plainData = new String(cipher.doFinal(inputByte));
    return plainData;
  }

  /**
    * @Description: 私钥签名
    * @param plainData 明文
    * @param privateKey base64的私钥
    * @return: java.lang.String
    * @author: 宋海燕(songhaiyan@bjca.org.cn)
    * @date: 2021/1/26 17:37
    */
  public static String sign(String plainData, String privateKey) throws Exception {
    Signature signature = Signature.getInstance(algorithm);
    //base64编码的公钥
    byte[] decoded = Base64.getDecoder().decode(privateKey);
    PrivateKey priKey =  KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
    //用私钥初始化signature
    signature.initSign(priKey);
    //更新原始字符串
    signature.update(plainData.getBytes("UTF-8"));
    byte[] bytes = signature.sign();
    String sign = Base64.getEncoder().encodeToString(bytes);
    return sign;
  }

  /**
    * @Description: 公钥验签
    * @param plainData 明文
    * @param publicKey base64的公钥
    * @param sign 签名值
    * @return: java.lang.String
    * @author: 宋海燕(songhaiyan@bjca.org.cn)
    * @date: 2021/1/26 17:29
    */
  public static boolean verify(String plainData, String publicKey, String sign) throws Exception {
    Signature signature = Signature.getInstance(algorithm);
    //base64编码的公钥
    byte[] decoded = Base64.getDecoder().decode(publicKey);
    PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    //用公钥初始化signature
    signature.initVerify(pubKey);
    //更新原始字符串
    signature.update(plainData.getBytes("UTF-8"));
    //校验签名是否正确
    boolean result = signature.verify(Base64.getDecoder().decode(sign));
    return result;
  }
}

