package com.google.code.encryptionutils;


import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

public class EncryptRSAUtils extends EncryptUtils {
	private static final String RSA_STRATEGY = "RSA";
	
	private final Cipher cipher;
	private final KeyFactory factory;
	
	private Key publicKey;
	private Key privateKey;
	
	public EncryptRSAUtils(EncodingStrategy encodingStrategy, String encodedPublicKey, String encodedPrivateKey) throws Exception {
		super(encodingStrategy);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		factory = KeyFactory.getInstance(RSA_STRATEGY, "BC");
		cipher = Cipher.getInstance(RSA_STRATEGY, "BC");
		if (encodedPublicKey != null) {
			publicKey = readPublicKey(readKeyParts(encodedPublicKey));
		}
		if (encodedPrivateKey != null) {
			privateKey = readPrivateKey(readKeyParts(encodedPrivateKey));
		}
	}
	
	byte[] encrypt(String input) {
		try {
			return rsaEncrypt(input.getBytes("UTF-8"));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	String decrypt(byte[] input) {
		try {
			return new String(rsaDecrypt(input), "UTF-8");
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private byte[] rsaEncrypt(byte[] data) throws Exception {
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return cipher.doFinal(data);
	}
	
	private byte[] rsaDecrypt(byte[] data) throws Exception {
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(data);
	}
	
	private BigInteger[] readKeyParts(String encodedData) throws Exception {
		ObjectInputStream oin = new ObjectInputStream(new ByteArrayInputStream(decode(encodedData)));
		try {
			BigInteger m = (BigInteger) oin.readObject();
			BigInteger e = (BigInteger) oin.readObject();
			return new BigInteger[] { m, e };
		} finally {
			oin.close();
		}
	}

	private PublicKey readPublicKey(BigInteger[] parts) throws Exception {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(parts[0], parts[1]);
		return factory.generatePublic(keySpec);
	}
	
	private PrivateKey readPrivateKey(BigInteger[] parts) throws Exception {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(parts[0], parts[1]);
		return factory.generatePrivate(keySpec);
	}
	
	List<String> generateKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_STRATEGY);
			kpg.initialize(1024);
			KeyPair kp = kpg.genKeyPair();
			
			RSAPublicKeySpec pub = factory.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
			RSAPrivateKeySpec priv = factory.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);
			
			byte[] pubData = writeKeyParts(pub.getModulus(), pub.getPublicExponent());
			byte[] priData = writeKeyParts(priv.getModulus(), priv.getPrivateExponent());
			return Arrays.asList(encode(pubData), encode(priData));
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private byte[] writeKeyParts(BigInteger mod, BigInteger exp) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(out));
		oout.writeObject(mod);
		oout.writeObject(exp);
		oout.close();
		return out.toByteArray();
	}
}
