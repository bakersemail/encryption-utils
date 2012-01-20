package com.google.code.encryptionutils;

import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class EncryptAESUtils extends EncryptUtils {
	private final Cipher cipher;
	private final SecretKeySpec skeySpec;
	
	public EncryptAESUtils(EncodingStrategy encodingStrategy, String key) {
		super(encodingStrategy);
		
		try {
			cipher = Cipher.getInstance("AES");
			
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			byte[] bKey = new byte[16];
			//128bit sha-1 key
			System.arraycopy(sha.digest(key.getBytes("UTF-8")), 0, bKey, 0, 16);
			skeySpec = new SecretKeySpec(bKey, "AES");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public byte[] encrypt(String input) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			return cipher.doFinal(input.getBytes("UTF-8"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	@Override
	public String decrypt(byte[] input) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			return new String(cipher.doFinal(input), "UTF-8");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
