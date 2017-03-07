package com.samlai.security.xEs;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;


public class PbeStudy {
	/**
	 * PBE算法结合了消息摘要算法和对称加密算法的优点
	 * PBE(Password Based Encryption)基于口令加密  -- Salt
	 * 对已有算法的包装
	 * JDK BC
	 * 盐
	 * PBEWithMD5AndDES
	 */
	private static String STR = "one type of security:PBE";
	
	public static void main(String[] args) {
		jdkPBE();
	}
	
	
	
	//jdk实现PBE
	public static void jdkPBE(){
		try {
			//初始化盐
			SecureRandom random=new SecureRandom();
			byte[] salt=random.generateSeed(8);
			
			//口令与密钥
			String password="studySecurity";
			PBEKeySpec pbeKeySpec=new PBEKeySpec(password.toCharArray());
			SecretKeyFactory factory=SecretKeyFactory.getInstance("PBEWITHMD5andDES");
			Key key=factory.generateSecret(pbeKeySpec);
			
			//加密
			PBEParameterSpec pbeParameterSpec=new PBEParameterSpec(salt, 100);
			Cipher cipher=Cipher.getInstance("PBEWITHMD5andDES");
			cipher.init(Cipher.ENCRYPT_MODE, key,pbeParameterSpec);
			byte[] result=cipher.doFinal(STR.getBytes());
			System.out.println("jdk PBE encode: "+Base64.encodeBase64String(result));
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, key,pbeParameterSpec);
			result=cipher.doFinal(result);
			System.out.println("jdk PBE decode: "+new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
