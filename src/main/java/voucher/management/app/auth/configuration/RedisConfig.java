package voucher.management.app.auth.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
public class RedisConfig {

	@Value("${spring.redis.host}")
	private String redisHost;

	@Bean
	public String getRedisHost() {
		return redisHost;
	}

	@Value("${spring.redis.port}")
	private int redisPort;

	@Bean
	public int getRedisPort() {
		return redisPort;
	}

	@Value("${spring.redis.ssl}")
	private boolean redisSSL;

	@Bean
	public boolean getRedisSSL() {
		return redisSSL;
	}

	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		LettuceConnectionFactory lettuceConnectionFactory = new LettuceConnectionFactory(redisHost, redisPort);

		lettuceConnectionFactory.setUseSsl(redisSSL);

		return lettuceConnectionFactory;
	}

	@Bean
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory redisConnectionFactory) {
        StringRedisTemplate template = new StringRedisTemplate(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
        return template;
    }
}
