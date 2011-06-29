package com.google.code.encryptionutils;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EncryptAESUtils extends EncryptUtils {
	private Cipher cipher;
	private SecretKeySpec skeySpec;
	
	public EncryptAESUtils(EncodingStrategy encodingStrategy, String key) {
		super(encodingStrategy);
		
		try {
			cipher = Cipher.getInstance("AES");
			
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			//128bit sha-1 key
			byte[] bKey = Arrays.copyOf(sha.digest(key.getBytes("UTF-8")), 16);
			skeySpec = new SecretKeySpec(bKey, "AES");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] encrypt(String input) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			return cipher.doFinal(input.getBytes("UTF-8"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	public String decrypt(byte[] input) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			return new String(cipher.doFinal(input), "UTF-8");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
