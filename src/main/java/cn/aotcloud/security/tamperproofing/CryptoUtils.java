package cn.aotcloud.security.tamperproofing;

import cn.aotcloud.crypto.sm.SM3PcodeEncoder;
import cn.aotcloud.crypto.sm.SM3TextEncryptor;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 加密工具类
 *
 * @author xkxu
 */
public class CryptoUtils {

	/**
	 * 创建一个SM3加密实现对象
	 *
	 * @return SM3
	 */
	public static TextEncryptor createSM3TextEncryptor() {
		return new SM3TextEncryptor();
	}

	public static PasswordEncoder createSm3PasswordEncoder() {
		return new SM3PcodeEncoder();
	}
}
