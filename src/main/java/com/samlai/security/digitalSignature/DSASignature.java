package com.samlai.security.digitalSignature;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class DSASignature {
	/**
	 * 	DSS(Digital signature Standard)数字签名标准
	 * 	DSA(Digital signature ALgorithm)数字签名算法
	 * 	DSA仅包含数字签名
	 */

	private static String STR = "one type of security:DSA Signature";
	
	public static void main(String[] args) {
		jdkDSA();
	}

	private static void jdkDSA() {
		try {
			//1.初始化密钥
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("DSA");
			keyPairGenerator.initialize(512);
			KeyPair keyPair=keyPairGenerator.generateKeyPair();
			DSAPublicKey dsaPublicKey=(DSAPublicKey) keyPair.getPublic();
			DSAPrivateKey dsaPrivateKey=(DSAPrivateKey) keyPair.getPrivate();

			System.out.println("public Key: "+Base64.encodeBase64String(dsaPublicKey.getEncoded()));
			System.out.println("private Key: "+Base64.encodeBase64String(dsaPrivateKey.getEncoded()));
			
			//2.执行签名
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(dsaPrivateKey.getEncoded());
			KeyFactory keyFactory=KeyFactory.getInstance("DSA");
			PrivateKey privateKey=keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			Signature signature=Signature.getInstance("SHA1withDSA");
			signature.initSign(privateKey);
			signature.update(STR.getBytes());
			byte[] result=signature.sign();
			System.out.println("jdk DSA sign"+Hex.encodeHexString(result));
			
			//3.验证签名
			X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(dsaPublicKey.getEncoded());
			keyFactory=KeyFactory.getInstance("DSA");
			PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
			signature=Signature.getInstance("SHA1withDSA");
			signature.initVerify(publicKey);
			signature.update(STR.getBytes());
			
			boolean bool=signature.verify(result);
			
			System.out.println("jdk DSA verify: "+bool);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
