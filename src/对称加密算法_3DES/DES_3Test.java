package 对称加密算法_3DES;

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
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
			//keyGenerator.init(168); //或者下面的一行
			keyGenerator.init(new SecureRandom());//生成默认长度
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			//key转换
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertSecretKey = factory.generateSecret(desKeySpec);
			//加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk 3des encrypt:"+Hex.encodeHexString(result));
			//解密
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
			//生成key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede","BC");
			System.out.println(keyGenerator.getProvider());
			keyGenerator.init(168);
			SecretKey secretKey = keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			//key转换
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
			Key convertSecretKey = factory.generateSecret(desKeySpec);
			//加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS7Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc 3des encrypt:"+Hex.encodeHexString(result));
			//解密
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc 3des decrypt:"+new String(result));
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}
