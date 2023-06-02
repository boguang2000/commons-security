package cn.aotcloud.security.oncetoken;


import java.util.Locale;

/**
 * @author xkxu
 */
public enum OnceProtocol {


    simple, once2;

    public static final String TOKEN_HEADER_NAME_V2 = "X-Ac-Once-Token";

    public static final String TOKEN_HEADER_NAME = "X-Request-Token";

    public static final String TIME_HEADER_NAME = "X-Request-Time";

    public static final String SIGN_HEADER_NAME = "X-Request-Sign";

    public static final String TOKEN_PARAM_NAME_V2 = TOKEN_HEADER_NAME_V2.toLowerCase(Locale.ENGLISH).replaceAll("-", "_");

    public static final String TOKEN_PARAM_NAME = TOKEN_HEADER_NAME.toLowerCase(Locale.ENGLISH).replaceAll("-", "_");

    public static final String TIME_PARAM_NAME = TIME_HEADER_NAME.toLowerCase(Locale.ENGLISH).replaceAll("-", "_");

    public static final String SIGN_PARAM_NAME = SIGN_HEADER_NAME.toLowerCase(Locale.ENGLISH).replaceAll("-", "_");

}
