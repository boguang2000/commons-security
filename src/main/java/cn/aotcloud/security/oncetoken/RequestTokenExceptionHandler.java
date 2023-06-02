package cn.aotcloud.security.oncetoken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author xkxu
 */
public interface RequestTokenExceptionHandler {

	/**
	 * @param request
	 * @param response
	 * @param exception
	 */
	public void handle(HttpServletRequest request, HttpServletResponse response, 
			IllegalRequestTokenException exception) throws IOException;
}
