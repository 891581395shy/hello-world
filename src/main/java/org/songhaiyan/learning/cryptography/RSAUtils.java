package org.songhaiyan.learning.cryptography;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
import org.apache.commons.codec.binary.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import org.junit.Test;

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
  private static final int KEY_SIZE_1024 = 1024;
  private static final String SHA256WITHRSA = "SHA256withRSA";
  private static final String RSA = "RSA";

  //用于封装随机产生的公钥与私钥的base64
  private static Map<Integer, String> keyMap = new HashMap<>();

  /***
    * @Description 测试加密、解密
    * @return void
    * @author 宋海燕(songhaiyan@bjca.org.cn)
    * @date 2021/9/24 16:32
    */
  @Test
  public void testCrypto() throws Exception {
    System.out.println("----------------测试加密、解密-------------------");
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
  /***
    * @Description 测试签名、验签
    * @return void
    * @author 宋海燕(songhaiyan@bjca.org.cn)
    * @date 2021/9/24 16:30
    */
  @Test
  public void testSignAndVerify() throws Exception {
    System.out.println("----------------测试签名、验签-------------------");
    //生成公钥和私钥
    genKeyPair();
    //加密字符串
    String message = "RSA测试ABCD~!@#$";
    //私钥签名
    String sign = sign(message, keyMap.get(1));
    System.out.println("私钥签名，sign:" + sign);
    //公钥参与验签
    boolean result = verify(message, keyMap.get(0), sign);
    System.out.println( "公钥参与验签，verify result: " + result);
  }

  /***
    * @Description 测试生成随机公私钥
    * @return void
    * @author 宋海燕(songhaiyan@bjca.org.cn)
    * @date 2021/9/24 16:40
    */
  @Test
  public void testSaveKeyPair() throws Exception {
    System.out.println("----------------测试生成随机公私钥-------------------");
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);

    keyPairGenerator.initialize(KEY_SIZE_1024);

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
    String nStr = Base64.encodeBase64String(N.toByteArray());
    String eStr = Base64.encodeBase64String(e.toByteArray());
    String dStr = Base64.encodeBase64String(d.toByteArray());
    String nStrPri = Base64.encodeBase64String(Npri.toByteArray());
    System.out.println("公钥（e,N）, 私钥（d,N）");
    System.out.println("特征值：N，e，d");
    System.out.println("nStr:   " + nStr);
    System.out.println("eStr:" + eStr);
    System.out.println("dStr:" + dStr);
    System.out.println("nStrPri:" + nStrPri);
    System.out.println("nStr是否等于nStrPri" + nStrPri.endsWith(nStr));

    /*将这三个字符串保存到文件或者数据库，通常n，e可以保存在客户端，而n，d的数据必须保存在服务端*/

    N = new BigInteger(Base64.decodeBase64(nStr));
    e = new BigInteger(Base64.decodeBase64(eStr));
    d = new BigInteger(Base64.decodeBase64(dStr));
    System.out.println("N:" + N);
    System.out.println("e:" + e);
    System.out.println("d:" + d);

    /*根据N，e生成公钥*/
    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(N, e);
    PublicKey pbk = KeyFactory.getInstance(RSA).generatePublic(publicKeySpec);

    Cipher cipher = Cipher.getInstance(RSA);
    cipher.init(Cipher.ENCRYPT_MODE, pbk);
    //bytes 是加密后的数据
    byte[] bytes = cipher.doFinal("helloWorld".getBytes());
    //用base64转换输出
    System.out.println("加密数据：" + Base64.encodeBase64String(bytes));

    /*根据N，d生成私钥*/
    RSAPrivateKeySpec ps = new RSAPrivateKeySpec(N, d);
    PrivateKey prk = KeyFactory.getInstance(RSA).generatePrivate(ps);

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
  public static void genKeyPair() throws NoSuchAlgorithmException {
    // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RSA);
    // 初始化密钥对生成器，密钥大小为96-1024位  
    keyPairGen.initialize(KEY_SIZE_1024, new SecureRandom());
    // 生成一个密钥对，保存在keyPair中
    KeyPair keyPair = keyPairGen.generateKeyPair();
    // 得到私钥
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    // 得到公钥
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    // 得到私钥字符串
    String privateKeyBase64Str = Base64.encodeBase64String(privateKey.getEncoded());
    // 得到公钥字符串
    String publicKeyBase64Str = Base64.encodeBase64String(publicKey.getEncoded());
    // 将公钥和私钥保存到Map
    //0表示公钥
    keyMap.put(0, publicKeyBase64Str);
    //1表示私钥
    keyMap.put(1, privateKeyBase64Str);
  }

  /**
   * @Description: RSA公钥加密
   * @param: plainData 明文
   * @param: publicKeyBase64 base64的公钥
   * @return: java.lang.String base64的密文
   * @author: 宋海燕(songhaiyan @ bjca.org.cn)
   * @date: 2021/1/26 11:51
   */

  public static String encrypt(String plainData, String publicKeyBase64) throws Exception {
    //base64编码的公钥
    byte[] publicKey = Base64.decodeBase64(publicKeyBase64);
    RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(publicKey));
    //RSA加密
    Cipher cipher = Cipher.getInstance(RSA);
    cipher.init(Cipher.ENCRYPT_MODE, pubKey);

    return Base64.encodeBase64String(cipher.doFinal(plainData.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * @Description: RSA私钥解密
   * @param: cipherTextBase64 base64的密文
   * @param: privateKeyBase64 base64的私钥
   * @return: java.lang.String 明文
   * @author: 宋海燕(songhaiyan @ bjca.org.cn)
   * @date: 2021/1/26 12:25
   */

  public static String decrypt(String cipherTextBase64, String privateKeyBase64) throws Exception {
    //解base64后的密文
    byte[] cipherText = Base64.decodeBase64(cipherTextBase64);
    //私钥
    byte[] privateKey = Base64.decodeBase64(privateKeyBase64);
    RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    //RSA解密
    Cipher cipher = Cipher.getInstance(RSA);
    cipher.init(Cipher.DECRYPT_MODE, priKey);
    return new String(cipher.doFinal(cipherText));
  }

  /**
    * @Description: 私钥签名
    * @param plainData 明文
    * @param privateKeyBase64 base64的私钥
    * @return: java.lang.String base64的签名值
    * @author: 宋海燕(songhaiyan@bjca.org.cn)
    * @date: 2021/1/26 17:37
    */
  
  public static String sign(String plainData, String privateKeyBase64) throws Exception {
    Signature signature = Signature.getInstance(SHA256WITHRSA);
    //base64编码的公钥
    byte[] privateKey = Base64.decodeBase64(privateKeyBase64);
    PrivateKey priKey = KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    //用私钥初始化signature
    signature.initSign(priKey);
    //更新原始字符串
    signature.update(plainData.getBytes(StandardCharsets.UTF_8));
    byte[] bytes = signature.sign();
    return Base64.encodeBase64String(bytes);
  }

  /**
    * @Description: 公钥验签
    * @param plainData 明文
    * @param publicKeyBase64 base64的公钥
    * @param signBase64 签名值base64的签名值
    * @return: java.lang.String
    * @author: 宋海燕(songhaiyan@bjca.org.cn)
    * @date: 2021/1/26 17:29
    */
  public static boolean verify(String plainData, String publicKeyBase64, String signBase64) throws Exception {
    Signature signature = Signature.getInstance(SHA256WITHRSA);
    //base64编码的公钥
    byte[] publicKey = Base64.decodeBase64(publicKeyBase64);
    PublicKey pubKey = KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(publicKey));
    //用公钥初始化signature
    signature.initVerify(pubKey);
    //更新原始字符串
    signature.update(plainData.getBytes(StandardCharsets.UTF_8));
    //校验签名是否正确
    return signature.verify(Base64.decodeBase64(signBase64));
  }
}

