package com.samlai.security.asyEncry;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class DHStudy {
	/**
	 * 非对称加密算法 -DH(密钥交换)
	 *  对称加密带来的困扰
	 *  构建本地密钥
	 *  对称
	 */
	private static String STR = "one type of security:DH";
	
	public static void main(String[] args) {
		jdkDH();
		bcDH();
	}
	
	
	//jdk实现DH
	public static void jdkDH(){
		try {
			//初始化发送方密钥
			KeyPairGenerator senderKeyPairGenerator=KeyPairGenerator.getInstance("DH");
			senderKeyPairGenerator.initialize(512);
			KeyPair senderKeyPair=senderKeyPairGenerator.generateKeyPair();
			//发送方公钥，发送给收方(网络,文件)
			byte[] senderPublicKeyEnc=senderKeyPair.getPublic().getEncoded();
			
			//初始化接收方密钥
			KeyFactory receiverKeyFactory=KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(senderPublicKeyEnc);
			PublicKey receiverPublicKey=receiverKeyFactory.generatePublic(x509EncodedKeySpec);
			DHParameterSpec dhParameterSpec=((DHPublicKey)receiverPublicKey).getParams();
			KeyPairGenerator receiverKeyPairGenerator=KeyPairGenerator.getInstance("DH");
			receiverKeyPairGenerator.initialize(dhParameterSpec);
			KeyPair receiverKeyPair=receiverKeyPairGenerator.generateKeyPair();
			PrivateKey reveiverPrivateKey=receiverKeyPair.getPrivate();
			byte[] receiverPublicKeyEnc=receiverKeyPair.getPublic().getEncoded();
			
			//密钥构建
			KeyAgreement receiverKeyAgreement=KeyAgreement.getInstance("DH");
			receiverKeyAgreement.init(reveiverPrivateKey);
			receiverKeyAgreement.doPhase(receiverPublicKey, true);
			SecretKey receiverDesKey=receiverKeyAgreement.generateSecret("DES");
			
			KeyFactory senderKeyFactory=KeyFactory.getInstance("DH");
			x509EncodedKeySpec=new X509EncodedKeySpec(receiverPublicKeyEnc);
			PublicKey senderPublicKey=senderKeyFactory.generatePublic(x509EncodedKeySpec);
			KeyAgreement senderKeyAgreement=KeyAgreement.getInstance("DH");
			senderKeyAgreement.init(senderKeyPair.getPrivate());
			senderKeyAgreement.doPhase(senderPublicKey, true);
			SecretKey senderDesKey=senderKeyAgreement.generateSecret("DES");
			if(Objects.equals(receiverDesKey, senderDesKey)){
				System.out.println("双方密钥相同");
			}
			
			//加密
			Cipher cipher=Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
			byte[] result=cipher.doFinal(STR.getBytes());
			System.out.println("jdk DH encode: "+Base64.encodeBase64String(result));
			
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
			result=cipher.doFinal(result);
			System.out.println("jdk DH decode: "+new String(result));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	//bc实现DH算法
	public static void bcDH(){
		try {
			Security.addProvider(new BouncyCastleProvider());
			//初始化发送方密钥
			KeyPairGenerator senderKeyPairGenerator=KeyPairGenerator.getInstance("DH","BC");
			senderKeyPairGenerator.getProvider();
			senderKeyPairGenerator.initialize(512);
			KeyPair senderKeyPair=senderKeyPairGenerator.generateKeyPair();
			//发送方公钥，发送给收方(网络,文件)
			byte[] senderPublicKeyEnc=senderKeyPair.getPublic().getEncoded();
			
			//初始化接收方密钥
			KeyFactory receiverKeyFactory=KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(senderPublicKeyEnc);
			PublicKey receiverPublicKey=receiverKeyFactory.generatePublic(x509EncodedKeySpec);
			DHParameterSpec dhParameterSpec=((DHPublicKey)receiverPublicKey).getParams();
			KeyPairGenerator receiverKeyPairGenerator=KeyPairGenerator.getInstance("DH","BC");
			receiverKeyPairGenerator.getProvider();
			receiverKeyPairGenerator.initialize(dhParameterSpec);
			KeyPair receiverKeyPair=receiverKeyPairGenerator.generateKeyPair();
			PrivateKey reveiverPrivateKey=receiverKeyPair.getPrivate();
			byte[] receiverPublicKeyEnc=receiverKeyPair.getPublic().getEncoded();
			
			//密钥构建
			KeyAgreement receiverKeyAgreement=KeyAgreement.getInstance("DH");
			receiverKeyAgreement.init(reveiverPrivateKey);
			receiverKeyAgreement.doPhase(receiverPublicKey, true);
			SecretKey receiverDesKey=receiverKeyAgreement.generateSecret("DES");
			
			KeyFactory senderKeyFactory=KeyFactory.getInstance("DH");
			x509EncodedKeySpec=new X509EncodedKeySpec(receiverPublicKeyEnc);
			PublicKey senderPublicKey=senderKeyFactory.generatePublic(x509EncodedKeySpec);
			KeyAgreement senderKeyAgreement=KeyAgreement.getInstance("DH");
			senderKeyAgreement.init(senderKeyPair.getPrivate());
			senderKeyAgreement.doPhase(senderPublicKey, true);
			SecretKey senderDesKey=senderKeyAgreement.generateSecret("DES");
			if(Objects.equals(receiverDesKey, senderDesKey)){
				System.out.println("双方密钥相同");
			}
			
			//加密
			Cipher cipher=Cipher.getInstance("DES");
			cipher.init(Cipher.ENCRYPT_MODE, senderDesKey);
			byte[] result=cipher.doFinal(STR.getBytes());
			System.out.println("bc DH encode: "+Base64.encodeBase64String(result));
			
			
			//解密
			cipher.init(Cipher.DECRYPT_MODE, receiverDesKey);
			result=cipher.doFinal(result);
			System.out.println("bc DH decode: "+new String(result));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
