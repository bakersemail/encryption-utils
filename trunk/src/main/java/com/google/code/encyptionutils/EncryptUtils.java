package com.google.code.encyptionutils;



public abstract class EncryptUtils {
	private final EncodingStrategy encodingStrategy;
	
	EncryptUtils(EncodingStrategy encodingStrategy) {
		assert encodingStrategy != null : "Encoding strategy is required";
		this.encodingStrategy = encodingStrategy;
	}
	
	abstract byte[] encrypt(String input);
	
	abstract String decrypt(byte[] input);
	
	public String encode(byte[] b) {
		return encodingStrategy.encode(b);
	}

	public byte[] decode(String encoded) {
		return encodingStrategy.decode(encoded);
	}

	public String encryptAndEncode(String input) {
		return encode(encrypt(input));
	}
	
	public String decryptEncoded(String input) {
		return decrypt(decode(input));
	}
}
