package com.google.code.encryptionutils;



public abstract class EncryptUtils {
	private final EncodingStrategy encodingStrategy;
	
	protected EncryptUtils(EncodingStrategy encodingStrategy) {
		assert encodingStrategy != null : "Encoding strategy is required";
		this.encodingStrategy = encodingStrategy;
	}
	
	public abstract byte[] encrypt(String input);
	
	public abstract String decrypt(byte[] input);
	
	public final String encode(byte[] b) {
		return encodingStrategy.encode(b);
	}

	public final byte[] decode(String encoded) {
		return encodingStrategy.decode(encoded);
	}

	public final String encryptAndEncode(String input) {
		return encode(encrypt(input));
	}
	
	public final String decryptEncoded(String input) {
		return decrypt(decode(input));
	}
}
