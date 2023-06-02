package cn.aotcloud.security.transport.http;

import cn.aotcloud.security.transport.CryptoHttpInputMessage;
import cn.aotcloud.utils.HttpServletUtil;

import org.apache.commons.lang3.ArrayUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Vector;

/**
 * @author xkxu
 */
public class CryptoRequestWrapper extends HttpServletRequestWrapper {
	
    private Map<String, String[]> parameterMap = new HashMap<>();

    private final CryptoHttpInputMessage cryptoHttpInputMessage;

    private final HttpServletRequest request;

    public CryptoRequestWrapper(HttpServletRequest request, CryptoHttpInputMessage cryptoHttpInputMessage) {
        super(request);
        this.request = request;
        this.cryptoHttpInputMessage = cryptoHttpInputMessage;
        MultiValueMap<String, String> queryParams = cryptoHttpInputMessage.getQueryParams();
        parameterMap = HttpServletUtil.transferQueryParams(queryParams);
    }

    @Override
    public String getQueryString() {
        return cryptoHttpInputMessage.getQueryString();
    }

    // 重写几个HttpServletRequestWrapper中的方法

    /**
     * 获取所有参数名
     *
     * @return 返回所有参数名
     */
    @Override
    public Enumeration<String> getParameterNames() {
        Vector<String> vector = new Vector<>(parameterMap.keySet());
        return vector.elements();
    }

    /**
     * 获取指定参数名的值，如果有重复的参数名，则返回第一个的值 接收一般变量 ，如text类型
     *
     * @param name 指定参数名
     * @return 指定参数名的值
     */
    @Override
    public String getParameter(String name) {
        String[] results = parameterMap.get(name);
        return ArrayUtils.isEmpty(results) ? "" : results[0];
    }

    @Override
    public String[] getParameterValues(String name) {
        return parameterMap.get(name);
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return parameterMap;
    }

    public void setParameterMap(Map<String, String[]> parameterMap) {
        this.parameterMap = parameterMap;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (HttpMethod.GET.name().equals(request.getMethod())) {
            return super.getInputStream();
        }
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(read(cryptoHttpInputMessage.getBody()));

        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return false;
            }

            @Override
            public void setReadListener(ReadListener readListener) {

            }

            @Override
            public int read() {
                return byteArrayInputStream.read();
            }
        };
    }

    @Override
    public String getContentType() {
        return MediaType.APPLICATION_JSON_VALUE;
    }

    @Override
    public String getHeader(String name) {
        if (HttpHeaders.CONTENT_TYPE.equalsIgnoreCase(name)) {
            return MediaType.APPLICATION_JSON_VALUE;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (null != name && name.equalsIgnoreCase(HttpHeaders.CONTENT_TYPE)) {
            return new Enumeration<String>() {
                private boolean hasGetted = false;
                @Override
                public boolean hasMoreElements() {
                    return !hasGetted;
                }
                @Override
                public String nextElement() {
                    if (hasGetted) {
                        throw new NoSuchElementException();
                    } else {
                        hasGetted = true;
                        return MediaType.APPLICATION_JSON_VALUE;
                    }
                }
            };
        }
        return super.getHeaders(name);
    }
    private static byte[] read(InputStream inputStream) throws IOException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int num = inputStream.read(buffer);
            while (num != -1) {
                baos.write(buffer, 0, num);
                num = inputStream.read(buffer);
            }
            baos.flush();
            return baos.toByteArray();
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
        }
    }

}