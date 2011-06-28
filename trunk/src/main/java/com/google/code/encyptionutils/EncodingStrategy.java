package com.google.code.encyptionutils;



public interface EncodingStrategy {
	String encode(byte[] data);
	
	byte[] decode(String encoded);
}
