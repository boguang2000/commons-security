package cn.aotcloud.security.oncetoken.event;

import org.springframework.context.ApplicationEvent;

import cn.aotcloud.security.oncetoken.RequestToken;

/**
 * @author xkxu
 */
@SuppressWarnings("serial")
public class IllegalRequestTokenApplicationEvent extends ApplicationEvent {

	public IllegalRequestTokenApplicationEvent(Object source) {
		super(source);
	}

	public RequestToken getRequestToken() {
		return (RequestToken) getSource();
	}
}
