package voucher.management.app.auth.utility;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EncryptionUtils {

	@Value("${aes.secret.key}")
	private String aesSecretKey;
	
	private static final String AES_ALGORITHM = "AES";
	
	public String decrypt(String encryptedCode) throws Exception {
		byte[] bytekey = hexStringToByteArray(aesSecretKey.trim());
		SecretKeySpec sks = new SecretKeySpec(bytekey, AES_ALGORITHM);
		Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, sks);
		byte[] decrypted = cipher.doFinal(hexStringToByteArray(encryptedCode));
		String OriginalPassword = new String(decrypted);
		return OriginalPassword;
	}

	public String encrypt(String code) throws Exception {
		byte[] bytekey = hexStringToByteArray(aesSecretKey.trim());
		SecretKeySpec sks = new SecretKeySpec(bytekey,AES_ALGORITHM);
		Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, sks, cipher.getParameters());
		byte[] encrypted = cipher.doFinal(code.getBytes());
		String encryptedpwd = byteArrayToHexString(encrypted);
		return encryptedpwd;
	}
	
	private static String byteArrayToHexString(byte[] b) {
		StringBuffer sb = new StringBuffer(b.length * 2);
		for (int i = 0; i < b.length; i++) {
			int v = b[i] & 0xff;
			if (v < 16) {
				sb.append('0');
			}
			sb.append(Integer.toHexString(v));
		}
		return sb.toString().toUpperCase();
	}

	private static byte[] hexStringToByteArray(String s) {
		byte[] b = new byte[s.length() / 2];
		for (int i = 0; i < b.length; i++) {
			int index = i * 2;
			int v = Integer.parseInt(s.substring(index, index + 2), 16);
			b[i] = (byte) v;
		}
		return b;
	}
}
