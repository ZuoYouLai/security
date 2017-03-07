package com.samlai.security.xEs;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesStudy {
	/**
	 * 对称加密算法---DES
	 * 
	 */
	private static String STR = "one type of security:DES";

	public static void main(String[] args) {
		jdkDES();
		bcDES();
	}

	// jdk的DES
	public static void jdkDES() {
		try {
			// 生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			//打断点可以查看对应keyGenerator.getProvider()是哪个class：BC
			keyGenerator.getProvider();
			keyGenerator.init(56);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();

			// Key转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			Key converSecretKey = factory.generateSecret(desKeySpec);

			// 加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(STR.getBytes());
			System.out
					.println("jdk des encode: " + Hex.encodeHexString(result));

			// 解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk des decode: " + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	

	// bc方式的DES
	public static void bcDES() {
		try {
			
			Security.addProvider(new BouncyCastleProvider());
			
			// 生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES","BC");
			//打断点可以查看对应keyGenerator.getProvider()是哪个class：BC
			keyGenerator.getProvider();
			keyGenerator.init(56);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();

			// Key转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
			Key converSecretKey = factory.generateSecret(desKeySpec);

			// 加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(STR.getBytes());
			System.out
					.println("bc des encode: " + Hex.encodeHexString(result));

			// 解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc des decode: " + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
