package com.samlai.security.Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;

public class SHAMessageDigestStudy {
	/**
	 * 消息摘要算法--SHA
	 * 	  安全散列算法
	 * 	SHA-1,SHA-2(SHA-224,SHA-256,SHA-384,SHA-512)
	 * 	算法       	摘要长度         实现方
	 * 	SHA-1   160     JDK
	 *  SHA-224 224     Bouncy Castle
	 *  SHA-256 256     JDK
	 *  SHA-384 384     JDK
	 *  SHA-512 512     JDK
	 */
	private static String STR = "one type of security:SH-X";
	
	public static void main(String[] args) {
		jdkSHA1();
		bcSHA1();
		bcSHA224();
		ccSHA1();
	}
	
	//Jdk的SHA1算法
	public static void jdkSHA1() {
		try {
			MessageDigest md=MessageDigest.getInstance("SHA");
			md.update(STR.getBytes());
			System.out.println("jdk sha-1:"+Hex.encodeHexString(md.digest()));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	
	//bc的SHA1算法
	public static void bcSHA1() {
		 Digest digest=new SHA1Digest();
		 digest.update(STR.getBytes(),0,STR.getBytes().length);
		 byte[] sha1Bytes=new byte[digest.getDigestSize()];
		 digest.doFinal(sha1Bytes, 0);
		 System.out.println("bc SHA-1:  "+Hex.encodeHexString(sha1Bytes));
	}
	
	
	//bc的SHA224算法
	public static void bcSHA224() {
		Digest digest=new SHA224Digest();
		digest.update(STR.getBytes(),0,STR.getBytes().length);
		byte[] sha1Bytes=new byte[digest.getDigestSize()];
		digest.doFinal(sha1Bytes, 0);
		System.out.println("bc SHA-224:  "+Hex.encodeHexString(sha1Bytes));
	}
	
	//cc的SHA1算法
	public static void ccSHA1(){
		System.out.println("cc SHA1 1: "+DigestUtils.sha1Hex(STR.getBytes()));
		System.out.println("cc SHA1 2: "+DigestUtils.sha1Hex(STR));
	}
	
	

}
