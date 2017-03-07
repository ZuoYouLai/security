package com.samlai.security.Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;

//消息摘要算法
public class MessageDigestStudy {
	/**
	 * MD(Message Digest) 
	 * 		MD家族(128位摘要信息) -MD2,MD4 
	 * 	类型: 
	 * 		算法     长度         实现方
	 * 		MD2-128位-JDK
	 * 		MD4-128位-Boundcy Castle 
	 * 		MD5-128位-JDK
	 * 
	 * SHA(Secure Hash Algorithm) MAC(Message Authentication Code) 验证数据的完整性
	 * 数字签名核心算法
	 */
	private static String STR = "one type of security:MD-X";

	public static void main(String[] args) {
		jdkMd5();
		jdkMd2();
		bcMd4();
		bcMd2();
		bcMd5();
		ccMd5();
		ccMd2();
	}

	// jdkMd5
	public static void jdkMd5() {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5Bytes = md.digest(STR.getBytes());
			// 借助cc的算法来进行md5的加密出对应的字符串
			System.out.println("JDK MD5: " + Hex.encodeHexString(md5Bytes));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	// jdkMd2
	public static void jdkMd2() {
		try {
			MessageDigest md = MessageDigest.getInstance("MD2");
			byte[] md5Bytes = md.digest(STR.getBytes());
			// 借助cc的算法来进行md2的加密出对应的字符串
			System.out.println("JDK MD2: " + Hex.encodeHexString(md5Bytes));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	// bcMd4
	public static void bcMd4() {
		Digest digest = new MD4Digest();
		digest.update(STR.getBytes(), 0, STR.getBytes().length);
		byte[] md4Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md4Bytes, 0);
		System.out.println("bc Md4: " + Hex.encodeHexString(md4Bytes));
	}

	// bcMd2
	public static void bcMd2() {
		Digest digest = new MD2Digest();
		digest.update(STR.getBytes(), 0, STR.getBytes().length);
		byte[] md4Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md4Bytes, 0);
		System.out.println("bc Md2: " + Hex.encodeHexString(md4Bytes));
	}

	// bcMd5
	public static void bcMd5() {
		Digest digest = new MD5Digest();
		digest.update(STR.getBytes(), 0, STR.getBytes().length);
		byte[] md4Bytes = new byte[digest.getDigestSize()];
		digest.doFinal(md4Bytes, 0);
		System.out.println("bc Md5: " + Hex.encodeHexString(md4Bytes));
	}

	// ccMD5
	public static void ccMd5() {
		System.out.println("CC MD5: " + DigestUtils.md5Hex(STR.getBytes()));
	}

	// ccMD2
	public static void ccMd2() {
		System.out.println("CC MD2: " + DigestUtils.md2Hex(STR.getBytes()));
	}

}
