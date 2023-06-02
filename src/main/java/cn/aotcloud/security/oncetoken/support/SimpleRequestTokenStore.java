package cn.aotcloud.security.oncetoken.support;

import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

import cn.aotcloud.security.oncetoken.RequestToken;
import cn.aotcloud.security.oncetoken.RequestTokenStore;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * @author xkxu
 */
@EnableScheduling
public class SimpleRequestTokenStore implements RequestTokenStore {
	
	//private LoggerHandle logger = LoggerHandle.Instance(getClass());
	
	private ConcurrentMap<String, RequestToken> map = new ConcurrentHashMap<>();

	@Override
	public RequestToken getToken(String tokenFromRequest) {
		return map.get(tokenFromRequest);
	}

	@Override
	public void save(RequestToken requestToken) {
		map.put(requestToken.getToken(), requestToken);
	}

	@Override
	public void remove(String requestToken) {
		map.remove(requestToken);
	}

	@Override
	@Scheduled(fixedDelay=30000)
	//@SchedulerLock(name = "requestTokenStoreScheduledTask", lockAtMostFor = "PT30M", lockAtLeastFor = "PT20M")
	public void clear() {
		//logger.debug("开始清理过期的一次性令牌。");
		if (!map.isEmpty()) {
			List<String> removedToken = new ArrayList<>();
			map.forEach((key, value) -> {
				if (value.isExpired()) {
					removedToken.add(key);
				}
			});
			if (!removedToken.isEmpty()) {
				removedToken.forEach((key) -> {
					map.remove(key);
				});
				//logger.debug("清理过期了{}个一次性令牌。", removedToken.size());
			}
		}
	}

}
