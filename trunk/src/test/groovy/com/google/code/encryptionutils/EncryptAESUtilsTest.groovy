package com.google.code.encryptionutils

import org.junit.Test

class EncryptAESUtilsTest {
	static final String INPUT = "some input"
	static final ENCODING_STRATEGY = new Base32Encoding()
	
	EncryptUtils utils = new EncryptAESUtils(ENCODING_STRATEGY, "some key")
	
	@Test
	void shouldEncryptAndDecryptToSameInput() {
		def encrypted = utils.encrypt(INPUT)
		def decrypted = utils.decrypt(encrypted)
		
		assert decrypted == INPUT
	}
	
	@Test
	void shouldEncryptAndDecryptEncodedToSameInput() {
		def encrypted = utils.encryptAndEncode(INPUT)
		assert encrypted

		String decrypted = utils.decryptEncoded(encrypted)
		assert INPUT == decrypted
	}
	
	@Test
	void shouldEncodeAndDecodeToSameInput() {
		String encoded = utils.encode(INPUT.getBytes())
		
		String decoded = new String(utils.decode(encoded))
		assert decoded == INPUT
	}
}
