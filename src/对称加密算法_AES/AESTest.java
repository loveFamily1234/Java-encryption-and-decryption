package �ԳƼ����㷨_AES;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AESTest {
	private static String src = "imooc security AES";
	public static void main(String[] args) {
		jdkAES();
		bcAES();
	}
	public static void jdkAES(){
		try {
			//����KEY
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] keyBytes = secretKey.getEncoded();
			
			//keyת��
			Key key = new SecretKeySpec(keyBytes, "AES");
			
			//����
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk aes encrypt : "+Base64.encodeBase64String(result));
			
			//����
			cipher.init(Cipher.DECRYPT_MODE, key);
			result = cipher.doFinal(result);
			System.out.println("jdk aes decrypt : "+ new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public static void bcAES(){
		try {
			Security.addProvider(new BouncyCastleProvider());
			//����key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES","BC");
			System.out.println(keyGenerator.getProvider());
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			//keyת��
			Key key = new SecretKeySpec(bytesKey, "AES");
			//����
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc aes encrypt:"+Hex.encodeHexString(result));
			//����
			cipher.init(Cipher.DECRYPT_MODE, key);
			result = cipher.doFinal(result);
			System.out.println("bc aes decrypt:"+new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
