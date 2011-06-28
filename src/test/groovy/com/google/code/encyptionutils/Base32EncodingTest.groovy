package com.google.code.encyptionutils

import org.junit.Test

class Base32EncodingTest {
	static final String INPUT = "test"
	
	@Test
	void shouldEncodeBytesAndDecodeToSameInput() {
		Base32Encoding encoding = new Base32Encoding()
		
		String encoded = encoding.encode(INPUT.getBytes("UTF-8"))
		assert encoded != INPUT
		assert new String(encoding.decode(encoded), "UTF-8") == INPUT
	}
}
