package com.google.code.encryptionutils;


import org.apache.commons.codec.binary.Base32;

public class Base32Encoding implements EncodingStrategy {

	public String encode(byte[] data) {
		return new Base32().encodeAsString(data);
	}

	public byte[] decode(String encoded) {
		return new Base32().decode(encoded);
	}

}

