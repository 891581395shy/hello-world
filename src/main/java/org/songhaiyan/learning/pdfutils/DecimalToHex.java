package org.songhaiyan.learning.pdfutils;

import org.bouncycastle.util.encoders.Hex;

/**
 * @ClassName: DecimalToHex.java
 * @Description:
 * @Author: 宋海燕(songhaiyan @ bjca.org.cn)
 * @Date: 2021/5/12 14:47
 * @Version: V2.0.1
 **/
public class DecimalToHex {
  /***
    * @Description 10进制转16进制
    * @param args 
    * @return void
    * @author 宋海燕(songhaiyan@bjca.org.cn)
    * @date 2021/5/12 14:47
    */
  public static void main(String[] args) {
    byte[] bytes = new byte[16];
    for (int i = 2; i <= 17; i++) {
      bytes[i - 2] = (byte) (255 & i >> 0);
    }
    System.out.println(Hex.toHexString(bytes));
  }
}

