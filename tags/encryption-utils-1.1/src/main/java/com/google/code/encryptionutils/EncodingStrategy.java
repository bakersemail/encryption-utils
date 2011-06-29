package com.google.code.encryptionutils;



public interface EncodingStrategy {
	String encode(byte[] data);
	
	byte[] decode(String encoded);
}
