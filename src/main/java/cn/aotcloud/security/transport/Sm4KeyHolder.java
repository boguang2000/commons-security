package cn.aotcloud.security.transport;

import org.springframework.core.NamedThreadLocal;

/**
 * @author xkxu
 */
public class Sm4KeyHolder {

	private static NamedThreadLocal<String> sm4KeyThreadLocal = new NamedThreadLocal<String>("Sm4Key ThreadLocal");

	public static String getSm4Key() {
		return sm4KeyThreadLocal.get();
	}

	public static void setSm4Key(String sm4Key) {
		sm4KeyThreadLocal.set(sm4Key);
	}

	public static void clear() {
		sm4KeyThreadLocal.remove();
	}
}
