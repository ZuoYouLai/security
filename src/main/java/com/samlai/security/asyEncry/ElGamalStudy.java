package com.samlai.security.asyEncry;


import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;


import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ElGamalStudy {
	
	/**
	 * 基于离散对数
	 * 没有jdk实现，bc提供
	 * 公钥加密算法
	 * 密钥长度：8的倍数 160>
	 * 
	 */
	private static String STR = "one type of security:ElGamal";
	public static void main(String[] args) {
		bcElGamal();
	}
	//jdk实现RSA加密
	public static void bcElGamal(){
		try {
			Security.addProvider(new BouncyCastleProvider());
			//初始化密钥
			AlgorithmParameterGenerator algorithmParameterGenerator=AlgorithmParameterGenerator.getInstance("ElGamal");
			algorithmParameterGenerator.init(256);
			AlgorithmParameters algorithmParameters=algorithmParameterGenerator.generateParameters();
			DHParameterSpec dhParameterSpec=(DHParameterSpec)algorithmParameters.getParameterSpec(DHParameterSpec.class);
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("ElGamal");
			keyPairGenerator.initialize(dhParameterSpec,new SecureRandom());
			KeyPair keyPair=keyPairGenerator.generateKeyPair();
			//构建对应的密钥对
			PublicKey elGamalPublicKey=keyPair.getPublic();
			PrivateKey elGamalPrivateKey=keyPair.getPrivate();
			
			System.out.println("Public Key: "+Base64.encodeBase64String(elGamalPublicKey.getEncoded()));
			System.out.println("Private Key: "+Base64.encodeBase64String(elGamalPrivateKey.getEncoded()));;
			
			
			//步骤是：
			/**
			 * 1.在接收者上进行构建密钥对就是公钥跟私钥
			 * 2.由接收者进行发布公钥,再由发布者进行公钥进行加密数据,再进行传输加密数据
			 * 3.接收者进行接收数据,由私钥进行解密
			 */
			
			//公钥加密,私钥解密 ----- 加密
//			X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(elGamalPublicKey.getEncoded());
//			KeyFactory keyFactory=KeyFactory.getInstance("ElGamal");
//			PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
			Cipher cipher=Cipher.getInstance("ElGamal");
			cipher.init(Cipher.ENCRYPT_MODE, elGamalPublicKey);
			byte[] result=cipher.doFinal(STR.getBytes());
			System.out.println("ElGamals算法,公钥加密,私钥解密-----加密: "+Base64.encodeBase64String(result));
			
//			PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(elGamalPrivateKey.getEncoded());
//			keyFactory=KeyFactory.getInstance("ElGamal");
//			PrivateKey privateKey=keyFactory.generatePrivate(pkcs8EncodedKeySpec);
			cipher=Cipher.getInstance("ElGamal");
			cipher.init(Cipher.DECRYPT_MODE, elGamalPrivateKey);
			result=cipher.doFinal(result);
			System.out.println("ElGamals算法,公钥加密,私钥解密-----解密: "+new String(result));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
