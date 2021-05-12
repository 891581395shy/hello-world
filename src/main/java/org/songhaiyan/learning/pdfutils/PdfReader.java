package org.songhaiyan.learning.pdfutils;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URLDecoder;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.pdfparser.PDFParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.Before;
import org.junit.Test;

/**
 * @ClassName: PdfReader.java
 * @Description:
 * @Author: 宋海燕(songhaiyan @ bjca.org.cn)
 * @Date: 2021/2/4 14:24
 * @Version: V2.0.1
 **/
public class PdfReader {
  private String resourcesPath;
  String testPdfFilePath_Rsa;
  String testPdfFilePath_Sm2;

  @Before
  public void init() throws Exception {
    resourcesPath = URLDecoder.decode(this.getClass().getClassLoader().getResource("").getPath(), "UTF-8");
    testPdfFilePath_Rsa = resourcesPath + "pdf" + File.separator + "xss2.0-RSA.pdf";
    testPdfFilePath_Sm2 = resourcesPath + "pdf" + File.separator + "xss2.0-SM2.pdf";
  }

  @Test
  public void testpdf(){
    File pdfFile = new File(testPdfFilePath_Rsa);
    PDDocument pdDocument = null;
    try {
      //PDF文件加载有两种方式，无明显差异，方式二代码较简洁
      // 方式一：
//      InputStream input = new FileInputStream(pdfFile);
//      PDFParser pdfParser = new PDFParser((RandomAccessRead) input);
//      pdfParser.parse();
//      pdDocument = pdfParser.getPDDocument();

      // 方式二：
      pdDocument = PDDocument.load(pdfFile);

      // 获取页码
      int pages = pdDocument.getNumberOfPages();
      System.out.println("pages:" + pages);
      //读取文本内容
      PDFTextStripper stripper = new PDFTextStripper();
      //设置按顺序输出
      stripper.setSortByPosition(true);
      stripper.setStartPage(6);
      stripper.setEndPage(6);
      String content = stripper.getText(pdDocument);
      System.out.println(content);

    }catch (Exception e){
      System.out.println(e);
    }

  }

}

