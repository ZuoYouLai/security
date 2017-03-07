package com.samlai.security.xEs;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEBlockCipher.DESede;

public class ThreeDesStudy {
	/**
	 * 为什么使用3DES: 补充DES的不足,因为其违反了柯克霍夫原则,与安全性问题
	 * 优点: 1.密钥长度增强 2.迭代次数提高
	 */

	private static String STR = "one type of security:3DES";

	public static void main(String[] args) {
		jdk3DES();
		bc3DES();
	}

	// jdk的DES
	public static void jdk3DES() {
		try {
			// 生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			// 打断点可以查看对应keyGenerator.getProvider()是哪个class：BC
			keyGenerator.getProvider();
			// 长度比des长,比如168位
			// keyGenerator.init(168);
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();

			// Key转换
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key converSecretKey = factory.generateSecret(desKeySpec);

			// 加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(STR.getBytes());
			System.out.println("jdk 3des encode: "
					+ Hex.encodeHexString(result));

			// 解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk 3des decode: " + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// bc方式的3DES
	public static void bc3DES() {
		try {

			Security.addProvider(new BouncyCastleProvider());
			// 生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede", "BC");
			// 打断点可以查看对应keyGenerator.getProvider()是哪个class：BC
			keyGenerator.getProvider();
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();

			// Key转换
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key converSecretKey = factory.generateSecret(desKeySpec);

			// 加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, converSecretKey);
			byte[] result = cipher.doFinal(STR.getBytes());
			System.out
					.println("bc 3des encode: " + Hex.encodeHexString(result));

			// 解密
			cipher.init(Cipher.DECRYPT_MODE, converSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc 3des decode: " + new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
