package com.samlai.security.Digest;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.omg.IOP.Encoding;


//消息摘要算法-MAC
public class MACMessageDigest {
	/**
	 * MAC:Message Authentication Code
	 *     含有密钥的散列函数算法
	 *     融合MD,SHA
	 *     	 -MD系列:HMACMD2,HmacMd4,HmacMd5
	 *       -SHA系列：HmacSHA1,HmacSHA224,HmacSHA256,HmacSHA384,HmacSHA512
	 *       应用如：SecureCRT
	 */
	private static String STR = "one type of security:MAC";
	public static void main(String[] args) {
		jdkHmacMd5();
		bcHmacMd5();
	}
	
	//jdk hmac
	public static void jdkHmacMd5(){
		try {
			//初始化KeyGenerator
			KeyGenerator keyGenerator=KeyGenerator.getInstance("HmacMD5");
			//产生密钥
			SecretKey secretKey=keyGenerator.generateKey();
			//获取密钥
//			byte[] key=secretKey.getEncoded();
			byte[] key=Hex.decodeHex(new char[]{'a','a','a','a','a','a','a','a'});
			
			//还原密钥
			SecretKey restoreSecretKey=new SecretKeySpec(key, "HmacMD5");
			//实例化MAC
			Mac mac=Mac.getInstance(restoreSecretKey.getAlgorithm());
			//初始化Mac
			mac.init(restoreSecretKey);
			//执行摘要
			byte[] hmacMD5Bytes=mac.doFinal(STR.getBytes());
			System.out.println("jdk HmacMD5:"+Hex.encodeHexString(hmacMD5Bytes));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	//bc hmac
	public static void bcHmacMd5(){
		HMac hMac=new HMac(new MD5Digest());
		hMac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("samlai")));
		hMac.update(STR.getBytes(),0,STR.getBytes().length);
		//执行摘要
		byte[] hmacMD5bytes=new byte[hMac.getMacSize()];
		hMac.doFinal(hmacMD5bytes, 0);
		System.out.println("bc HmacMD5:"+Hex.encodeHexString(hmacMD5bytes));
	}
	
	
}
