package org.songhaiyan.learning.cryptography;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @ClassName: AESUtils.java
 * @Description: AES加解密
 * @Author: 宋海燕(songhaiyan @ bjca.org.cn)
 * @Date: 2021/9/29 13:41
 * @Version: V2.0.1
 **/
public class AESUtils {
  /**
    * @Description ECB模式加解密
    * @return void
    * @date 2021/9/29 14:55
    */
  @Test
  public void testCryptoByECB() throws Exception {
    /*
     * 此处使用AES-128-ECB加密模式，key需要为16位（128bit）。
     */
    System.out.println("***********ECB电码本模式 Electronic Codebook Book***********");
    System.out.println("这个模式是默认的，就只是根据密钥的位数，将数据分成不同的块进行加密，加密完成后，再将加密后的数据拼接起来");
    System.out.println("优点：简单、速度快、可并行");
    System.out.println("缺点：如果明文块相同，则生成的密文块也相同，这样会导致安全性降低");
    String cKey = "jkl;POIU1234++==";
    // 需要加密的字串
    String cSrc = "www.gowhere.so";
    System.out.println("原文是：" + cSrc);
    // 加密
    String enString = encryptByECB(cSrc, cKey);
    System.out.println("加密后的字串是：" + enString);
    // 解密
    String deString = decryptByECB(enString, cKey);
    System.out.println("解密后的字串是：" + deString);
  }

  /**
   * @Description CBC模式加解密
   * @return void
   * @date 2021/9/29 14:55
   */
  @Test
  public void testCryptoByCBC() throws Exception {
    /*
     * 加密用的Key 可以用26个字母和数字组成 使用AES-128-CBC加密模式，key需要为16位。
     */
    System.out.println("***********CBC密码分组链接模式 Cipher Block Chaining***********");
    System.out.println("初始向量必须是一个与密钥长度相等的数据");
    System.out.println("在第一次加密前，会使用初始化向量与第一块数据做异或运算，生成的新数据再进行加密");
    System.out.println("加密第二块之前，会拿第一块的密文数据与第二块明文进行异或运算后再进行加密");
    System.out.println("解密时也是在解密后，进行异或运算，生成最终的明文");
    System.out.println("由于在加密前和解密后都会做异或运算，因此我们的明文可以不用补全，不是16个字节的倍数也可以，CBC中会自动用0补全进行异或运算");
    System.out.println("由于自动进行了补全，所以解密出的数据也会在后面补全0，因此获取到数据时，需要将末尾的0去除，或者根据源数据长度来截取解密后的数据");
    System.out.println("优点：每次加密密钥不同，加强了安全性");
    System.out.println("缺点：加密无法并行运算，但是解密可以并行，必须在前一个块加密完成后，才能加密后块，并且也需要填充0在后面，所以并不适合流数据（不适合的原因可能是，需要满足128位的数据之后才能进行加密，这样后面才不会有0的补全）");
    System.out.println("缺点：如果前一个数据加密错误，那么后续的数据都是错的了");
    System.out.println("缺点：两端需要同时约定初始向量iv");
    /*
     * 加密用的Key 可以用26个字母和数字组成 使用AES-128-CBC加密模式，key需要为16位。
     */
    String cKey="hj7x89H$yuBI0456";
    String iv ="NIfb&95GUY86Gfgh";
    // 需要加密的字串
    String cSrc = "www.gowhere.so";
    System.out.println("原文是：" + cSrc);
    // 加密
    String enString = encryptByCBC(cSrc, cKey, iv);
    System.out.println("加密后的字串是：" + enString);
    // 解密
    String deString = decryptByCBC(enString, cKey, iv);
    System.out.println("解密后的字串是：" + deString);
  }

  /**
   * @Description CFB模式加解密
   * @return void
   * @date 2021/9/29 14:55
   */
  @Test
  public void testCryptoByCFB() throws Exception {
    System.out.println("***********CFB密码反馈模式 Cipher FeedBack");
    System.out.println("初始向量必须是一个与密钥长度相等的数据");
    System.out.println("优点：解密可同步，可以传入非16字节倍数的数据，适合流数据");
    System.out.println("缺点：解密的时候可以并行解密，但是加密的时候并不可以并行加密。并且也需要选择iv");
    String cKey = "jkl;POIU1234++==";
    // 需要加密的字串
    String cSrc = "www.gowhere.so";
    System.out.println("原文是：" + cSrc);
    // 加密
    String enString = encryptByECB(cSrc, cKey);
    System.out.println("加密后的字串是：" + enString);
    // 解密
    String deString = decryptByECB(enString, cKey);
    System.out.println("解密后的字串是：" + deString);
  }

  /**
   * @Description OFB模式加解密
   * @return void
   * @date 2021/9/29 14:55
   */
  @Test
  public void testCryptoByOFB() throws Exception {
    System.out.println("***********OFB输出反馈模式 Output FeedBack");
    System.out.println("初始向量必须是一个与密钥长度相等的数据");
    System.out.println("优点：解密可同步，可以传入非16字节倍数的数据，适合流数据");
    System.out.println("缺点：解密的时候可以并行解密，但是加密的时候并不可以并行加密。并且也需要选择iv");
    String cKey = "jkl;POIU1234++==";
    // 需要加密的字串
    String cSrc = "www.gowhere.so";
    System.out.println("原文是：" + cSrc);
    // 加密
    String enString = encryptByECB(cSrc, cKey);
    System.out.println("加密后的字串是：" + enString);
    // 解密
    String deString = decryptByECB(enString, cKey);
    System.out.println("解密后的字串是：" + deString);
  }

  /**
   * @Description CTR模式加解密
   * @return void
   * @date 2021/9/29 14:55
   */
  @Test
  public void testCryptoByCTR() throws Exception {
    System.out.println("***********CTR计算器模式 Counter");
    System.out.println("OFB不能并行的原因就在于需要上一次的iv进行加密后的结果，因此在CTR中我们将（iv+key）+key替换成了（iv+1）+key,这样我们就不需要依赖上一次的加密结果了");
    System.out.println("优点：由于加解密可以并行，因此CTR模式的加解密速度也很快");
    System.out.println("缺点：iv+1的获取比较负责，需要获取瞬时iv");
    String cKey = "jkl;POIU1234++==";
    // 需要加密的字串
    String cSrc = "www.gowhere.so";
    System.out.println("原文是：" + cSrc);
    // 加密
    String enString = encryptByECB(cSrc, cKey);
    System.out.println("加密后的字串是：" + enString);
    // 解密
    String deString = decryptByECB(enString, cKey);
    System.out.println("解密后的字串是：" + deString);
  }



  /**
    * @Description ECB模式加密
    * @param plaintext 明文
    * @param sKey 密钥
    * @return java.lang.String 密文的base64
    * @date 2021/9/29 14:11
    */
  public static String encryptByECB(String plaintext, String sKey) throws Exception {
    if (sKey == null) {
      System.out.print("Key为空null");
      return null;
    }
    // 判断Key是否为16位
    if (sKey.length() != 16) {
      System.out.print("Key长度不是16位");
      return null;
    }
    byte[] raw = sKey.getBytes(StandardCharsets.UTF_8);
    SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
    //"算法/模式/补码方式"
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
    byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
    //此处使用BASE64做转码功能，同时能起到2次加密的作用。
    return Base64.encodeBase64String(encrypted);
  }

  /**
    * @Description ECB模式解密
    * @param ciphertextBase64 密文的base64
    * @param sKey 密钥
    * @return java.lang.String
    * @date 2021/9/29 14:16
    */
  public static String decryptByECB(String ciphertextBase64, String sKey) throws Exception {
    try {
      // 判断Key是否正确
      if (sKey == null) {
        System.out.print("Key为空null");
        return null;
      }
      // 判断Key是否为16位
      if (sKey.length() != 16) {
        System.out.print("Key长度不是16位");
        return null;
      }
      byte[] raw = sKey.getBytes(StandardCharsets.UTF_8);
      SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, skeySpec);
      //先用base64解密
      byte[] ciphertext = Base64.decodeBase64(ciphertextBase64);
      try {
        byte[] original = cipher.doFinal(ciphertext);
        return new String(original, StandardCharsets.UTF_8);
      } catch (Exception e) {
        System.out.println(e);
      }
    } catch (Exception ex) {
      System.out.println(ex);
    }
      return null;
  }

  /**
   * @Description CBC模式加密
   * @param plaintext 明文
   * @param sKey 密钥
   * @param iv 初始向量
   * @return java.lang.String 密文的base64
   * @date 2021/9/29 14:11
   */
  public static String encryptByCBC(String plaintext, String sKey, String iv) throws Exception {
    if (sKey == null || null == iv) {
      System.out.print("Key为空null，或iv为空null");
      return null;
    }
    if (sKey.length() != 16|| iv.length() != 16) {
      System.out.print("Key长度不是16位，或iv长度不是16位");
      return null;
    }

    //"算法/模式/补码方式"
    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
    int blockSize = cipher.getBlockSize();
    byte[] dataBytes = plaintext.getBytes();
    int plaintextLength = dataBytes.length;
    if (plaintextLength % blockSize != 0) {
      plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
    }
    byte[] plaintextPadding = new byte[plaintextLength];
    System.arraycopy(dataBytes, 0, plaintextPadding, 0, dataBytes.length);

    byte[] raw = sKey.getBytes(StandardCharsets.UTF_8);
    SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
    // CBC模式，需要一个向量iv，可增加加密算法的强度
    IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivspec);
    byte[] encrypted = cipher.doFinal(plaintextPadding);
    //此处使用BASE64做转码功能，同时能起到2次加密的作用。
    return Base64.encodeBase64String(encrypted);
  }

  /**
   * @Description CBC模式解密
   * @param ciphertextBase64 密文的base64
   * @param sKey 密钥
   * @param iv 初始向量
   * @return java.lang.String
   * @date 2021/9/29 14:16
   */
  public static String decryptByCBC(String ciphertextBase64, String sKey, String iv) throws Exception {
    try {
      if (sKey == null || null == iv) {
        System.out.print("Key为空null，或iv为空null");
        return null;
      }
      if (sKey.length() != 16 || iv.length() != 16) {
        System.out.print("Key长度不是16位，或iv长度不是16位");
        return null;
      }
      byte[] raw = sKey.getBytes(StandardCharsets.UTF_8);
      SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
      IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivspec);
      //先用base64解密
      byte[] ciphertext = Base64.decodeBase64(ciphertextBase64);
      try {
        byte[] original = cipher.doFinal(ciphertext);
        return new String(original, StandardCharsets.UTF_8);
      } catch (Exception e) {
        System.out.println(e);
      }
    } catch (Exception ex) {
      System.out.println(ex);
    }
    return null;
  }

}

