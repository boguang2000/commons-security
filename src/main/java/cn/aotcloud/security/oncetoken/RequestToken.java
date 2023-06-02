package cn.aotcloud.security.oncetoken;

import java.io.Serializable;

/**
 * 代表一个请求令牌。主要用于防重放攻击，业务请求之前需要先申请一个请求令牌，将该请求令牌放到业务请求中。
 * 
 * 请求令牌只能使用一次。
 * 
 * @author xkxu
 */
public class RequestToken implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 5758910799273617165L;

	public static final RequestToken ILLEGAL_REQUEST_TOKEN = new RequestToken();

	private String protocol;

	private String token;
	
	private Long createTime;
	
	/**
	 * 有效期，默认15分钟
	 */
	private int expiresIn = 15;
	
	private String sign;
	
	public RequestToken() {
		this.createTime = System.currentTimeMillis();
	}
	
	public RequestToken(String token) {
		this();
		this.token = token;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public Long getCreateTime() {
		return createTime;
	}

	public int getExpiresIn() {
		return expiresIn;
	}

	public void setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;
	}
	
	public String getSign() {
		return sign;
	}

	public void setSign(String sign) {
		this.sign = sign;
	}

	public void setCreateTime(Long createTime) {
		this.createTime = createTime;
	}

	public boolean isExpired() {
		return (System.currentTimeMillis() - this.createTime) >= (expiresIn * 60 * 1000);
	}

	public String getProtocol() {
		return protocol;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}
}
