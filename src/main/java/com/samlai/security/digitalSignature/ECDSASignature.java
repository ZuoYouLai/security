package com.samlai.security.digitalSignature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class ECDSASignature {
	/**
	 * 微软
	 * Eliptic Curve Digital Signature 椭圆曲线数字签名算法
	 * 速度快,强度高,签名短
	 */
	private static String STR = "one type of security:ECDSA Signature";

	public static void main(String[] args) {
		ECDSA();
	}

	private static void ECDSA() {
		
		try {
			//初始化密钥
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("EC");
			keyPairGenerator.initialize(256);
			KeyPair keyPair=keyPairGenerator.generateKeyPair();
			ECPublicKey ecPublicKey=(ECPublicKey) keyPair.getPublic();
			ECPrivateKey ecPrivateKey=(ECPrivateKey) keyPair.getPrivate();
			
			System.out.println("public Key: "+Base64.encodeBase64String(ecPublicKey.getEncoded()));
			System.out.println("private Key: "+Base64.encodeBase64String(ecPrivateKey.getEncoded()));
			
			//执行签名
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(ecPrivateKey.getEncoded());
			KeyFactory keyFactory=KeyFactory.getInstance("EC");
			PrivateKey privateKey=keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			Signature signature=Signature.getInstance("SHA1withECDSA");
			signature.initSign(privateKey);
			signature.update(STR.getBytes());
			byte[] result=signature.sign();
			System.out.println("JDK ECDSA SIGN:"+Hex.encodeHexString(result));
			
			//验证签名
			X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(ecPublicKey.getEncoded());
			keyFactory=KeyFactory.getInstance("EC");
			PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
			signature=Signature.getInstance("SHA1withECDSA");
			signature.initVerify(publicKey);
			signature.update(STR.getBytes());
			boolean bool=signature.verify(result);
			
			System.out.println("jdk ECDSA verify: "+bool);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}
}
