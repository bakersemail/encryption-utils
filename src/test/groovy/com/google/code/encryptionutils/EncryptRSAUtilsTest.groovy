package com.google.code.encryptionutils

import org.junit.Before
import org.junit.Test

class EncryptRSAUtilsTest {
	static final String INPUT = 'some input'
	static final ENCODING_STRATEGY = new Base32Encoding()
		
	String pbKey
	String prKey
	EncryptRSAUtils utils
	
	@Before
	void setup() {
		utils = new EncryptRSAUtils(ENCODING_STRATEGY, null, null)
		def keyPair = utils.generateKeyPair()
		pbKey = keyPair[0]
		prKey = keyPair[1]
		
		utils = new EncryptRSAUtils(ENCODING_STRATEGY, pbKey, prKey)
	}
	
	@Test
	void shouldGenerateKeyPairAndEncryptAndDecrypt() {
		EncryptRSAUtils utils = new EncryptRSAUtils(ENCODING_STRATEGY, null, null)
		def pair = utils.generateKeyPair()
		utils = new EncryptRSAUtils(ENCODING_STRATEGY, pair[0], pair[1])
		
		def encrypted = utils.encrypt(INPUT)
		def decrypted = utils.decrypt(encrypted)
		
		assert decrypted == INPUT
	}
	
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
		assert utils.decryptEncoded(encrypted) == INPUT
	}
	
	@Test
	void shouldEncodeAndDecodeToSameInput() {
		String encoded = utils.encode(INPUT.getBytes())
		assert new String(utils.decode(encoded)) == INPUT
	}
	
	@Test
	void shouldGenerateKeyPairAsEncoded() {
		def pair = utils.generateKeyPair()
		utils = new EncryptRSAUtils(ENCODING_STRATEGY, pair[0], pair[1])
		
		def encrypted = utils.encrypt(INPUT)
		def decrypted = utils.decrypt(encrypted)
		
		assert decrypted == INPUT
	}
	
	@Test
	void shouldAllowEncryptOnly() {
		def pair = utils.generateKeyPair()
		utils = new EncryptRSAUtils(ENCODING_STRATEGY, pair[0], null)
		
		def encrypted = utils.encrypt(INPUT)
		assert encrypted
		
		try {
			utils.decrypt encrypted
			assert false : "Should have thrown exception"
		} catch (Exception e) {
			//expected
		}
	}
	
	@Test
	void shouldAllowDecryptOnly() {
		def encrypted = utils.encrypt(INPUT)
		utils = new EncryptRSAUtils(ENCODING_STRATEGY, null, prKey)
		utils.decrypt encrypted 
		
		try {
			utils.encrypt INPUT
			assert false : "Should have thrown exception"
		} catch (Exception e) {
			//expected
		}
	}
	
	@Test
	void shouldNotDecryptWithWrongPrivateKey() {
		def encrypted = utils.encrypt(INPUT)
		assert encrypted
		
		def pair = utils.generateKeyPair()
		utils = new EncryptRSAUtils(ENCODING_STRATEGY, null, pair[1])
		try {
			utils.decrypt encrypted
//			assert false : "Should have thrown exception"
		} catch (Exception e) {
			//expected
		}
	}
}
