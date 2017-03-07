package com.samlai.security.xEs;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESStudy {
	/**
	 * 比较普遍使用,效率比3DES效果高,安全性也比较高,高级,DES替代者
	 */
	private static String STR = "one type of security:AES";
	
	public static void main(String[] args) {
		jdkAES();
		bcAES();
	}
	
	//jdk实现：256位限制性政策性文件
	public static void jdkAES(){
		try {
			//生成key
			KeyGenerator keyGenerator=KeyGenerator.getInstance("AES");
			//可以是128 256
//			keyGenerator.init(new SecureRandom());
			keyGenerator.init(128);
			SecretKey secretKey=keyGenerator.generateKey();
			byte[] keyBytes=secretKey.getEncoded();
			//key的转换
			Key key=new SecretKeySpec(keyBytes, "AES");
			//加密
			Cipher cipher=Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result=cipher.doFinal(STR.getBytes());
			System.out.println("jdk AES encode: "+Base64.encodeBase64String(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key);
			result=cipher.doFinal(result);
			System.out.println("jdk AES decode："+new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
   //bc实现AES
   public static void bcAES(){
	   
	try {
		    Security.addProvider(new BouncyCastleProvider());
		    //生成key
		    KeyGenerator keyGenerator=KeyGenerator.getInstance("AES","BC");
		    keyGenerator.getProvider();
		   //可以是128 256
			keyGenerator.init(128);
			SecretKey secretKey=keyGenerator.generateKey();
			byte[] keyBytes=secretKey.getEncoded();
			//key的转换
			Key key=new SecretKeySpec(keyBytes, "AES");
			//加密
			Cipher cipher=Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result=cipher.doFinal(STR.getBytes());
			System.out.println("bc AES encode: "+Base64.encodeBase64String(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key);
			result=cipher.doFinal(result);
			System.out.println("bc AES decode："+new String(result));
	} catch (Exception e) {
		e.printStackTrace();
	}
	
   }
	
}
