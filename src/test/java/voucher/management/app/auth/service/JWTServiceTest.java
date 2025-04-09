package voucher.management.app.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import voucher.management.app.auth.configuration.JWTConfig;
import voucher.management.app.auth.repository.UserRepository;
import voucher.management.app.auth.service.impl.JWTService;
import voucher.management.app.auth.service.impl.UserService;
import java.lang.reflect.Field;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class JWTServiceTest {

	@InjectMocks
	private JWTService jwtService;
	
	private JWTConfig jwtConfig;
	private ApplicationContext context;

	private KeyPair keyPair;

	@InjectMocks
	private UserService userService;

	@Mock
	private UserRepository userRepository;

	// Control flag per test
	static ThreadLocal<String> pentestValue = ThreadLocal.withInitial(() -> "true");

	@DynamicPropertySource
	static void dynamicProperties(DynamicPropertyRegistry registry) {
		registry.add("pentest.enable", () -> pentestValue.get());
	}

	@BeforeEach
	public void setup() throws Exception {
		// Generate RSA key pair for testing

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		keyPair = keyGen.generateKeyPair();

		jwtConfig = mock(JWTConfig.class);
		context = mock(ApplicationContext.class);

		when(jwtConfig.getJWTPrivateKey())
				.thenReturn(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
		when(jwtConfig.getJWTPubliceKey())
				.thenReturn(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

		jwtService = new JWTService(jwtConfig, context);
		Field field = JWTService.class.getDeclaredField("pentestEnable");
		field.setAccessible(true);
		field.set(jwtService, "true");
	}

	@Test
	public void testGenerateAndValidateToken() throws Exception {
		String token = jwtService.generateToken("John", "john@example.com", "123", false);
		assertNotNull(token);

		UserDetails userDetails = mock(UserDetails.class);
		when(userDetails.getUsername()).thenReturn("john@example.com");

		boolean isValid = jwtService.validateToken(token, userDetails);
		assertTrue(isValid);
	}

	@Test
	public void testExtractUserId() throws Exception {
		String token = jwtService.generateToken("John", "john@example.com", "user123", false);
		String userId = jwtService.extractUserID(token);
		assertEquals("user123", userId);
	}

	@Test
	public void testExtractUsername() throws Exception {
		String token = jwtService.generateToken("John", "john@example.com", "user123", false);
		Claims claims = jwtService.extractAllClaims(token);
		assertEquals("John", claims.get(JWTService.CLAIM_USERNAME));
	}

	@Test
	public void testTokenExpiration() throws Exception {
		String token = jwtService.generateToken("John", "john@example.com", "user123", false);
		Date expiration = jwtService.extractExpiration(token);
		assertTrue(expiration.after(new Date()));
	}

	@Test
	public void testExtractUserIdFromExpiredToken() throws JwtException, IllegalArgumentException, Exception {
		// Generate an expired token
		Date now = new Date();
		Date issuedAt = new Date(now.getTime() - 60 * 60 * 1000); // 1 hour ago
		Date expiration = new Date(now.getTime() - 30 * 60 * 1000); // 30 mins ago

		String expiredToken = Jwts.builder().subject("expiredUser").claim(JWTService.CLAIM_USERNAME, "ExpiredUser")
				.issuedAt(issuedAt).expiration(expiration).signWith(keyPair.getPrivate()).compact();

		String userId = jwtService.extractUserIdAllowExpiredToken(expiredToken);
		assertEquals("expiredUser", userId);
	}
	
	

    @Test
    void testExtractUserNameFromExpiredToken() throws Exception {
        // Simulate ExpiredJwtException
    	Date now = new Date();
		Date issuedAt = new Date(now.getTime() - 60 * 60 * 1000); // 1 hour ago
		Date expiration = new Date(now.getTime() - 30 * 60 * 1000); // 30 mins ago

		String expiredToken = Jwts.builder().subject("expiredUser").claim(JWTService.CLAIM_USERNAME, "ExpiredUser")
				.issuedAt(issuedAt).expiration(expiration).signWith(keyPair.getPrivate()).compact();

		String userId = jwtService.extractUserNameAllowExpiredToken(expiredToken);
		assertEquals("ExpiredUser", userId);
    }
}
