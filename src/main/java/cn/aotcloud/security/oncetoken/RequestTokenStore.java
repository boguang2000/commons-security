package cn.aotcloud.security.oncetoken;

/**
 * @author xkxu
 */
public interface RequestTokenStore {
	
	public RequestToken getToken(String tokenFromRequest);

	public void save(RequestToken requestToken);
	
	public void remove(String requestToken);
	
	public void clear();
}
