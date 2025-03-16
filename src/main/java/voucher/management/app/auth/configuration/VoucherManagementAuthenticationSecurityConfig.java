package voucher.management.app.auth.configuration;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

import org.springframework.web.cors.CorsConfiguration;

import voucher.management.app.auth.jwt.JwtFilter;
import voucher.management.app.auth.service.impl.OAuth2AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class VoucherManagementAuthenticationSecurityConfig {
	private static final String[] SECURED_URLs = { "/api/**" };

	@Value("${frontend.url}")
	private String frontEndUrl;

	@Bean
	public String getFrontEndUrl() {
		return frontEndUrl;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Autowired 
	private JwtFilter jwtFilter;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.cors(cors -> {
			cors.configurationSource(request -> {
				CorsConfiguration config = new CorsConfiguration();
				config.setAllowedOrigins(List.of(frontEndUrl));
				config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "OPTIONS"));
				config.setAllowedHeaders(List.of("*"));
				config.applyPermitDefaultValues();
				return config;
			});
		}).headers(headers -> headers.addHeaderWriter(new StaticHeadersWriter("Access-Control-Allow-Origin", "*"))
				.addHeaderWriter(
						new StaticHeadersWriter("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, OPTIONS"))
				.addHeaderWriter(new StaticHeadersWriter("Access-Control-Allow-Headers", "*"))
				.addHeaderWriter(new HstsHeaderWriter(31536000, false, true)).addHeaderWriter((request, response) -> {
					response.addHeader("Cache-Control", "max-age=60, must-revalidate");
				})).csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(
						auth -> auth.requestMatchers(SECURED_URLs).permitAll().anyRequest().authenticated())
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
	            .oauth2Login(oauth2 -> 
	                oauth2
	                    .userInfoEndpoint(userInfo -> 
	                        userInfo.oidcUserService(oidcUserService())
	                    )
	                    .successHandler(oauth2AuthenticationSuccessHandler())
	            )
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
	            .build();
	}

	@Bean
    public OAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler(frontEndUrl);
    }

    @Bean
    public OidcUserService oidcUserService() {
        return new OidcUserService();
    }
    
	

}
