package org.songhaiyan.learning.pdfutils;

import com.itextpdf.text.Document;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Image;
import com.itextpdf.text.PageSize;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.BaseFont;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.PdfGState;
import com.itextpdf.text.pdf.PdfWriter;

/**
 * @ClassName: PdfUtils.java
 * @Description:
 * @Author: 宋海燕(songhaiyan @ bjca.org.cn)
 * @Date: 2021/2/4 14:20
 * @Version: V2.0.1
 **/
public class PdfUtils {
  public static void main(String[] args) throws Exception{
      //实现A4纸页面 并且横向显示（不设置则为纵向）
      Document document = new Document(PageSize.A4.rotate());
      PdfWriter pdfWriter = PdfWriter.getInstance(document,new FileOutputStream("E:\\pdftest\\111testAnyWritePDFSignFacade201977_0 - 副本.pdf"));
      // 打开文档
      document.open();
      // 创建第一页（如果只有一页的话，这一步可以省略）
      document.newPage();

      // 加入水印
      PdfContentByte waterMar = pdfWriter.getDirectContentUnder();
      // 开始设置水印
      waterMar.beginText();
      // 设置水印透明度
      PdfGState gs = new PdfGState();
      // 设置笔触字体不透明度为0.4f
      gs.setStrokeOpacity(0.4f);
      try {
        Image image = Image.getInstance("E:\\pdftest\\陈龙.png");
        // 设置坐标 绝对位置 X Y
        image.setAbsolutePosition(200, 300);
        // 设置旋转弧度
        image.setRotation(30);// 旋转 弧度
        // 设置旋转角度
        image.setRotationDegrees(45);// 旋转 角度
        // 设置等比缩放
        image.scalePercent(90);// 依照比例缩放
        // image.scaleAbsolute(200,100);//自定义大小
        // 设置透明度
        waterMar.setGState(gs);
        // 添加水印图片
        waterMar.addImage(image);
        // 设置透明度
        waterMar.setGState(gs);
        //结束设置
        waterMar.endText();
        waterMar.stroke();
      } catch (IOException e) {
        e.printStackTrace();
      }finally {
        waterMar = null;
        gs = null;
      }

      // 加入文档内容
//      document.add(new Paragraph("my first pdf demo"));

      // 关闭文档
      document.close();
      pdfWriter.close();
  }
}

