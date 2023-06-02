package cn.aotcloud.security.config;

import com.google.common.collect.Lists;

import cn.aotcloud.security.oncetoken.OnceProtocol;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.Ordered;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.util.UrlPathHelper;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

@ConfigurationProperties(prefix = "sgitg.safe")
public class SgitgSafeProperties {

    private boolean fastjsonSafeMode = true;

    private TamperProofingParams tamperProofing = new TamperProofingParams();

    private HttpCrypto httpCrypto = new HttpCrypto();

    private RequestTokenProperties requestToken = new RequestTokenProperties();

    public boolean isFastjsonSafeMode() {
		return fastjsonSafeMode;
	}

	public void setFastjsonSafeMode(boolean fastjsonSafeMode) {
		this.fastjsonSafeMode = fastjsonSafeMode;
	}

	public TamperProofingParams getTamperProofing() {
        return tamperProofing;
    }

    public void setTamperProofing(TamperProofingParams tamperProofing) {
        this.tamperProofing = tamperProofing;
    }

    public HttpCrypto getHttpCrypto() {
		return httpCrypto;
	}

	public void setHttpCrypto(HttpCrypto httpCrypto) {
		this.httpCrypto = httpCrypto;
	}

	public RequestTokenProperties getRequestToken() {
        return requestToken;
    }

    public void setRequestToken(RequestTokenProperties requestToken) {
        this.requestToken = requestToken;
    }

    public static class TamperProofingParams {
    	
        private boolean enabled = false;
        
        // 防篡改白名单，不进行检查，业务系统需要根据实际情况修改
        private List<String> ignored = Lists.newArrayList(
        		"/x-ac-loginSuccess",
        		"/x-ac-ticket",
        		"/x-ac-platform",
        		"/x-ac-wxqrloginSuccess",
        		"/x-ac-wxlogin",
        		"/wxqrlogin",
        		"/common/initConfig",
        		"/common/publicConfig",
        		"/safeConf/**",
        		"/reboot",
        		"/health",
        		"/refresh",
        		"/env",
        		"/env-items",
        		"/routes",
        		"/info",
        		"/error/throw",
        		"/error/filterThrow",
        		"/file/oper/upload",
        		"/app/icon/upload",
        		"/appStat/exportAppStat",
        		"/appStat/exportAppMsg",
        		"/acActuator/**",
        		"/dataMigration/**",
        		"/driver/dataMigration/**",
        		"/statistics/**",
        		"/openapi/**",
        		"/zxing/**",
        		"/sys/**",
        		"/logger/**",
        		"/nodeMgr/**",
        		"/fileData/**",
        		"/test/**",
        		"/saas/auth"
        );

        Integer order;

        public TamperProofingParams() {
        }

        public boolean isEnabled() {
            return this.enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getIgnored() {
            return this.ignored;
        }

        public void setIgnored(List<String> ignored) {
            this.ignored.addAll(ignored);
        }

        public Integer getOrder() {
            return order;
        }

        public void setOrder(Integer order) {
            this.order = order;
        }
    }

    public static class HttpCrypto {
    	
    	private AntPathMatcher antPathMatcher = new AntPathMatcher();
    	
    	private UrlPathHelper urlPathHelper = new UrlPathHelper();
    	
    	// 请求解密功能的url控制列表，有黑白名单两种机制，include为黑名单，exclude为白名单，默认值为exclude。
    	private UrlMatchMode urlMatchMode = UrlMatchMode.exclude;

        private List<String> urls = Lists.newArrayList(
        		"/x-ac-loginSuccess",
        		"/x-ac-ticket",
        		"/x-ac-platform",
        		"/x-ac-wxqrloginSuccess",
        		"/x-ac-wxlogin",
        		"/wxqrlogin",
        		"/safeConf/**",
        		"/common/initConfig",
        		"/common/publicConfig",
        		"/error/throw",
        		"/error/filterThrow",
        		"/loading",
        		"/reboot",
        		"/acActuator/**",
        		"/dataMigration/**",
        		"/driver/dataMigration/**",
        		"/statistics/**",
        		"/openapi/**",
        		"/zxing/**",
        		"/sys/**",
        		"/logger/**",
        		"/nodeMgr/downloadLogfile",
        		"/fileData/**",
        		"/test/**",
        		"/saas/auth"
        );

        private boolean enabled;

        private int order = Ordered.HIGHEST_PRECEDENCE + 100;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public UrlMatchMode getUrlMatchMode() {
            return urlMatchMode;
        }

        public void setUrlMatchMode(UrlMatchMode urlMatchMode) {
            this.urlMatchMode = urlMatchMode;
        }

        public List<String> getUrls() {
            return urls;
        }

        public void setUrls(List<String> urls) {
            this.urls.addAll(urls);
        }
        
        public boolean shouldCrypto(HttpServletRequest request) {
        	String requestUri = urlPathHelper.getLookupPathForRequest(request);
        	return shouldCrypto(requestUri);
        }
        
        /**
         * @updater ZSQ	修改支持通配符
         * @param url
         * @return
         */
        private boolean shouldCrypto(String url) {
            if (urlMatchMode == UrlMatchMode.exclude) {
                return !doPtternUri(url);
            } else {
                return doPtternUri(url);
            }
        }
        
        /**
         * 修改支持使用通配符过滤
         * 
         * @author ZSQ
         * @param uri
         * @return
         */
        private boolean doPtternUri(String uri) {
        	for (String pattern : urls) {
        		if(antPathMatcher.match(pattern, uri)) {
        			return true;
        		}
			}
        	return false;
        }

        public int getOrder() {
            return order;
        }

        public void setOrder(int order) {
            this.order = order;
        }

    }

    public static enum UrlMatchMode {

        include, exclude;
    }

    public static class RequestTokenProperties {

        private boolean enabled;

        // 配置需要防重放保护的url列表，与files当中的列表取并集。
        private List<String> urls = new ArrayList<>();

        // 配置需要防重放保护的url列表，业务系统需要根据实际情况修改
        private List<String> files = Lists.newArrayList("classpath:/META-INF/app-center-anti-replay-urls.txt");

        private RequestTokenProperties.Schedule schedule;

        /**
         * 时间间隔
         */
        private int timeintervalSeconds = 60;

        private int ordered = Ordered.HIGHEST_PRECEDENCE + 180;

        /**
         * 支持的协议，如果为空，则支持所有协议
         */
        private List<OnceProtocol> supportedProtocols = new ArrayList<>();

        private String salt = "dfj84543dsws";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getUrls() {
            return urls;
        }

        public void setUrls(List<String> urls) {
            this.urls.addAll(urls);
        }

        public RequestTokenProperties.Schedule getSchedule() {
            return schedule;
        }

        public void setSchedule(RequestTokenProperties.Schedule schedule) {
            this.schedule = schedule;
        }

        public List<String> getFiles() {
            return files;
        }

        public void setFiles(List<String> files) {
            this.files.addAll(files);
        }

        public int getTimeintervalSeconds() {
            return timeintervalSeconds;
        }

        public void setTimeintervalSeconds(int timeintervalSeconds) {
            this.timeintervalSeconds = timeintervalSeconds;
        }

        public int getOrdered() {
            return ordered;
        }

        public void setOrdered(int ordered) {
            this.ordered = ordered;
        }

        public List<OnceProtocol> getSupportedProtocols() {
            return supportedProtocols;
        }

        public void setSupportedProtocols(List<OnceProtocol> supportedProtocols) {
            this.supportedProtocols = supportedProtocols;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }

        public static class Schedule {

            private boolean enabled;

            public boolean isEnabled() {
                return enabled;
            }

            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }
        }
    }
}
