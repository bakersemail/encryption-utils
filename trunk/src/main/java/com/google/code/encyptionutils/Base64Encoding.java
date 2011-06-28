package com.google.code.encyptionutils;

import org.apache.commons.codec.binary.Base64;

public class Base64Encoding implements EncodingStrategy {

	public String encode(byte[] data) {
		return new Base64().encodeAsString(data);
	}

	public byte[] decode(String encoded) {
		return new Base64().decode(encoded);
	}

}