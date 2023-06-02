package cn.aotcloud.security.transport;

import org.springframework.http.MediaType;

/**
 * @author xkxu
 */
public class CryptoMediaType extends MediaType {

    /**
	 * 
	 */
	private static final long serialVersionUID = -5310147537323187130L;

	/**
     * A String equivalent of {@link #APPLICATION_SM4_PUBLIC_FORM_URLENCODED}.
     */
    public final static String APPLICATION_SM4_PUBLIC_FORM_URLENCODED_VALUE = "application/x-ac-sm4-public-form-urlencoded";

    /**
     * Public constant media type for {@code application/x-ac-sm2-public-form-urlencoded}.
     */
    public final static MediaType APPLICATION_SM4_PUBLIC_FORM_URLENCODED;

    /**
     * A String equivalent of {@link #APPLICATION_SM4_PUBLIC_JSON}.
     * @see #APPLICATION_SM4_PUBLIC_JSON_UTF8_VALUE
     */
    public final static String APPLICATION_SM4_PUBLIC_JSON_VALUE = "application/x-ac-sm4-public-json";

    /**
     * Public constant media type for {@code application/x-ac-sm2-public-json}.
     */
    public final static MediaType APPLICATION_SM4_PUBLIC_JSON;

    /**
     * A String equivalent of {@link #APPLICATION_SM4_PUBLIC_JSON_UTF8}.
     */
    public final static String APPLICATION_SM4_PUBLIC_JSON_UTF8_VALUE = "application/x-ac-sm4-public-json;charset=UTF-8";

    /**
     * Public constant media type for {@code application/x-ac-sm2-public-json;charset=UTF-8}.
     */
    public final static MediaType APPLICATION_SM4_PUBLIC_JSON_UTF8;

    static {
        APPLICATION_SM4_PUBLIC_FORM_URLENCODED = valueOf(APPLICATION_SM4_PUBLIC_FORM_URLENCODED_VALUE);
        APPLICATION_SM4_PUBLIC_JSON = valueOf(APPLICATION_SM4_PUBLIC_JSON_VALUE);
        APPLICATION_SM4_PUBLIC_JSON_UTF8 = valueOf(APPLICATION_SM4_PUBLIC_JSON_UTF8_VALUE);
    }

    public CryptoMediaType(String type) {
        super(type);
    }

}
