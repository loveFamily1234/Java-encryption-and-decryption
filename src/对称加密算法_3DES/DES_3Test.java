package �ԳƼ����㷨_3DES;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DES_3Test {
	private static String src= "imooc security 3des";
	public static void main(String[] args) {
		jdk3DES();
		bc3DES();
	}
	public static void jdk3DES(){
		try {
			//����key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			//keyGenerator.init(168); //���������һ��
			keyGenerator.init(new SecureRandom());//����Ĭ�ϳ���
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			//keyת��
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertSecretKey = factory.generateSecret(desKeySpec);
			//����
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk 3des encrypt:"+Hex.encodeHexString(result));
			//����
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk 3des decrypt:"+new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
	private static void bc3DES(){
		try {
			Security.addProvider(new BouncyCastleProvider());
			//����key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");
			System.out.println(keyGenerator.getProvider());
			keyGenerator.init(168);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			//keyת��
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertSecretKey = factory.generateSecret(desKeySpec);
			//����
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS7Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc 3des encrypt:"+Hex.encodeHexString(result));
			//����
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc 3des decrypt:"+new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}
