package voucher.management.app.auth.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JWTConfig {

	@Value("${jwt.private.key}")
	private String jwtPrivateKey;

	@Value("${jwt.public.key}")
	private String jwtPublicKey;

	@Bean
	public String getJWTPrivateKey() {
		return jwtPrivateKey.replaceAll("\\s", "");
	}

	@Bean
	public String getJWTPubliceKey() {
		return jwtPublicKey.replaceAll("\\s", "");
	}

}
