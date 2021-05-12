package org.songhaiyan.learning;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @ClassName: LogUtils.java
 * @Description:
 * @Author: 宋海燕(songhaiyan @ bjca.org.cn)
 * @Date: 2021/2/25 17:24
 * @Version: V2.0.1
 **/
public class LogUtils {
  /**
   * 日志
   */
  protected Logger logger = LoggerFactory.getLogger(getClass());
  
  public void logUt(String args){
    logger.debug("日志打印*********:" + args);
    logger.info("日志打印********************-------:" + args);
  }

  public static void main(String[] args){

      LogUtils logUtils = new LogUtils();
    for (int i = 0; i < 40; i++) {
      logUtils.logUt(i+"");
    }
  }

}

