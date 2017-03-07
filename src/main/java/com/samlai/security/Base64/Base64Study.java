package com.samlai.security.Base64;

import java.io.IOException;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
//Base64算法
//应用：证书，密钥，email
public class Base64Study {

	/**
	 * 加密应用:
	 * 	 1.Base64算法
	 *   2.消息摘要算法
	 *   3.对称加密算法
	 *   4.非对称加密算法
	 *   5.数字签名算法
	 *   6.数字证书
	 *   7.安全协议
	 * 
	 * 3种方式进行加密解密处理：
	 *  	1.原生的JDK方式
	 *  	2.Bouncy Castle
	 *  		-两种支持方案:A.配置 2.调用
	 *      3.Commons Codec
	 *      	-Apache
	 *      	-Base64,二进制,十六进制,字符集编码
	 *      	-Url编码/解码
	 */
	
	private static String STR="one type of security:Base64";
	
	public static void main(String[] args) {
		//JDK方式实现
		jdkDoBase64();
		//CC实现的方式
		commonsCodecBase64();
		//BC实现的方式
		bouncyCastleBase64();
	}
	
	
	//JDK方式实现
	public static void jdkDoBase64(){
		try {
			BASE64Encoder encoder=new BASE64Encoder();
			String encode=encoder.encode(STR.getBytes());
			System.out.println("jdk encode:  "+encode);
			BASE64Decoder decoder=new BASE64Decoder();
			System.out.println("jdk decode:  "+new String(decoder.decodeBuffer(encode)));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	//Commons Codec方式实现
	public static void commonsCodecBase64(){
		byte[] encodeBytes=Base64.encodeBase64(STR.getBytes());
		System.out.println("cc encode:  "+new String(encodeBytes));
		byte[] decodeBytes=Base64.decodeBase64(encodeBytes);
		System.out.println("cc decode:  "+new String(decodeBytes));
	}
	
	//Bouncy Castle方式实现
	public static void bouncyCastleBase64(){
		byte[] encodeBytes=org.bouncycastle.util.encoders.Base64.encode(STR.getBytes());
		System.out.println("bc encode: "+new String(encodeBytes));
		byte[] decodeBytes=org.bouncycastle.util.encoders.Base64.decode(encodeBytes);
		System.out.println("bc decode: "+new String(decodeBytes));
	}
	
	
	
	
	
}
