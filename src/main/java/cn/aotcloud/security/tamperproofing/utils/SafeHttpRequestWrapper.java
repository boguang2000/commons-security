package cn.aotcloud.security.tamperproofing.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.lang3.StringUtils;

import cn.aotcloud.utils.IOUtils;

public class SafeHttpRequestWrapper extends HttpServletRequestWrapper {
	
	private Map<String, String[]> paramValuesMap = new HashMap<String, String[]>();
	
	private byte[] buffer = null;

	public SafeHttpRequestWrapper(HttpServletRequest request) throws IOException {
		super(request);
		String method = request.getMethod();
		if(StringUtils.equalsIgnoreCase(method, "GET")) {
			paramValuesMap.putAll(request.getParameterMap());
			copyInputStream();
		} else if(StringUtils.equalsIgnoreCase(method, "POST") && ServletUtils.isXwwwFormUrlencoded(this)) {
			paramValuesMap.putAll(request.getParameterMap());
			copyInputStream();
		} else if(StringUtils.equalsIgnoreCase(method, "POST") && !ServletUtils.isXwwwFormUrlencoded(this) && !ServletUtils.isMultipartFormData(this)) {
			paramValuesMap.putAll(request.getParameterMap());
			copyInputStream();
		} else if(StringUtils.equalsIgnoreCase(method, "POST") && ServletUtils.isMultipartFormData(this)) {
			copyInputStream();
		} else {
			//if (ServiceFactoryUtil.getServiceFactory().getLog().isErrorEnabled()) {
			//	ServiceFactoryUtil.getServiceFactory().getLog().error("Request Method:"+method+" Not Allow");
			//}
		}
	}

	public void setBuffer(byte[] buffer) {
		this.buffer = buffer;
	}
	
	@Override
	public Enumeration<String> getParameterNames() {
		return super.getParameterNames();
	}

	@Override
	public String[] getParameterValues(String name) {
		return this.paramValuesMap.get(name);
	}

	public void setParameterValues(String name, String[] values) {
		this.paramValuesMap.put(name, values);
	}
	
	public void removeParameter(String name) {
		this.paramValuesMap.remove(name);
	}
	
	@Override
	public Map<String, String[]> getParameterMap() {
		return this.paramValuesMap;
	}

	@Override
	public String getParameter(String name) {
		if (this.paramValuesMap.get(name) == null) {
			return null;
		} else {
			return this.paramValuesMap.get(name)[0];
		}
	}

	@Override
    public ServletInputStream getInputStream() throws IOException {
		if(this.buffer != null) {
			return new ServletBufferInputStream(this.buffer);
		} else {
			return null;
		}
    }
	
	@Override
	public BufferedReader getReader() throws IOException {
		return new BufferedReader(new InputStreamReader(this.getInputStream(), ServletUtils.readCharacterEncoding(this)));
	}
	
	/**
	 * 备份流
	 * @throws IOException
	 */
	public void copyInputStream() throws IOException {
		InputStream is = null;
		try {
			is = super.getInputStream();
			if(is != null) {
				this.buffer = IOUtils.toByteArray(is);
			}
		} finally {
			IOUtils.closeQuietly(is);
		}
	}
}
