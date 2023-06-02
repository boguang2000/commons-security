package cn.aotcloud.security.oncetoken.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import cn.aotcloud.security.oncetoken.IllegalRequestTokenException;
import cn.aotcloud.security.oncetoken.RequestTokenExceptionHandler;

import java.io.IOException;

/**
 * @author xkxu
 */
public class SimpleRequestTokenExceptionHandler implements RequestTokenExceptionHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			IllegalRequestTokenException exception) throws IOException {
		throw exception;
	}

}
