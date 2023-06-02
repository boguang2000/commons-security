package cn.aotcloud.security.transport;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author xkxu
 */
public class CryptoHttpInputMessage implements HttpInputMessage {

    private HttpHeaders headers;

    private InputStream body;

    private String queryString;

    private MultiValueMap<String, String> queryParams;

    public CryptoHttpInputMessage() {
    }

    public CryptoHttpInputMessage(InputStream body, HttpHeaders headers) {
        Assert.notNull(body, "InputStream must not be null");
        Assert.notNull(headers, "headers must not be null");
        this.body = body;
        this.headers = headers;
    }

    @Override
    public HttpHeaders getHeaders() {
        return this.headers;
    }

    @Override
    public InputStream getBody() throws IOException {
        return this.body;
    }

    public void setHeaders(HttpHeaders headers) {
        this.headers = headers;
    }

    public void setBody(InputStream body) {
        this.body = body;
    }

    public void setBody(byte[] contents) {
        this.body = new ByteArrayInputStream(contents != null ? contents : new byte[0]);
    }

    public String getQueryString() {
        return queryString;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
        this.queryParams = UriComponentsBuilder.fromUriString("http://localhost/")
                .query(queryString).build().getQueryParams();
    }

    public MultiValueMap<String, String> getQueryParams() {
        return queryParams;
    }

}
