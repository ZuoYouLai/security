package com.samlai.security.digitalSignature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class RSASignature {
	
	private static String STR = "one type of security:RSA Signature";
	
	public static void main(String[] args) {
		jdkRSA();
	}

	private static void jdkRSA() {
		try {
			//初始化密钥对
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(512);
			KeyPair keyPair=keyPairGenerator.generateKeyPair();
			RSAPublicKey rsaPublicKey=(RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey rsaPrivateKey=(RSAPrivateKey) keyPair.getPrivate();
			
			System.out.println("public Key: "+Base64.encodeBase64String(rsaPublicKey.getEncoded()));
			System.out.println("private Key: "+Base64.encodeBase64String(rsaPrivateKey.getEncoded()));
			
			//执行签名
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
			KeyFactory keyFactory=KeyFactory.getInstance("RSA");
			PrivateKey privateKey=keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			Signature signature=Signature.getInstance("MD5withRSA");
			signature.initSign(privateKey);
			signature.update(STR.getBytes());
			byte[] result=signature.sign();
			System.out.println("jdk RSA sign: "+Hex.encodeHexString(result));
			
			//验证签名
			X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(rsaPublicKey.getEncoded());
			keyFactory=KeyFactory.getInstance("RSA");
			PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
			signature=Signature.getInstance("MD5withRSA");
			signature.initVerify(publicKey);
			signature.update(STR.getBytes());
			boolean bool=signature.verify(result);
			
			System.out.println("jdk RSA verify: "+bool);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
