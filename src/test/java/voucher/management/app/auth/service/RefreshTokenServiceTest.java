package voucher.management.app.auth.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import jakarta.transaction.Transactional;
import voucher.management.app.auth.entity.RefreshToken;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.repository.RefreshTokenRepository;
import voucher.management.app.auth.service.impl.JWTService;
import voucher.management.app.auth.service.impl.RefreshTokenService;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.utility.GeneralUtility;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
public class RefreshTokenServiceTest {

	@Mock
	private UserService userService;

	@Mock
	private JWTService jwtService;

	@Mock
	private RefreshTokenRepository refreshTokenRepository;

	@InjectMocks
	private RefreshTokenService refreshTokenService;

//	@Mock
//	private GeneralUtility generalUitlity;

	private String userId;
	private String token;
	private String hashedToken;
	private User user;
	private Date expiryDate;
	private LocalDateTime localExpiryDateTime;
	private Boolean revoked;
	private static final String PLAIN_TOKEN = "rawToken123";
	private static final String HASHED_TOKEN = "hashedToken456";


	@BeforeEach
	void setUp() throws Exception {
		refreshTokenService = new RefreshTokenService(userService, refreshTokenRepository);
		userId = "user123";
		token = "sample.jwt.token";
		hashedToken = "hashedSampleToken"; // Assume this is the expected hashed value

		user = new User();
		user.setUserId(userId);

		expiryDate = new Date(System.currentTimeMillis() + 1000 * 60 * 60); // 1 hour expiry
		localExpiryDateTime = expiryDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
		revoked = true;
	}

	@Test
	void testUpdateRefreshTokenSuccess() {
		// Mock static utility method
		mockStatic(GeneralUtility.class);
		when(GeneralUtility.hashWithSHA256(token)).thenReturn(hashedToken);

		// Call the method
		assertDoesNotThrow(() -> refreshTokenService.updateRefreshToken(token, revoked));

	}

	@Test
	void testUpdateRefreshTokenException() {
		
		String rawToken = "sample_token";

		when(GeneralUtility.hashWithSHA256(rawToken)).thenThrow(new RuntimeException("Hashing failed"));

		RuntimeException exception = assertThrows(RuntimeException.class, () -> {
			refreshTokenService.updateRefreshToken(rawToken, true);
		});

		assertEquals("Error updating refresh token", exception.getMessage());
		verify(refreshTokenRepository, never()).updateRefreshToken(anyBoolean(), any(), any());
	}
	

	@Test
	void testSaveRefreshToken_Success() throws Exception {
		// Mock utility method
		when(GeneralUtility.hashWithSHA256(token)).thenReturn(hashedToken);

		// Mock service calls
		when(userService.findByUserId(userId)).thenReturn(user);
		when(jwtService.extractExpiration(token)).thenReturn(expiryDate);

		// Call the method
		assertDoesNotThrow(() -> refreshTokenService.saveRefreshToken(userId, token));

	}

	@Test
	void testValidRefreshTokenShouldReturnTrue() throws Exception {
		RefreshToken token = new RefreshToken();
		token.setRevoked(false);
		token.setExpiryDate(LocalDateTime.now().plusMinutes(10));

		boolean result = refreshTokenService.verifyRefreshToken(token);

		assertTrue(result);
	}
	
	@Test
	void testExpiredNotRevokedShouldCallUpdateAndThrowException() {
		RefreshToken token = new RefreshToken();
		token.setRevoked(false);
		token.setExpiryDate(LocalDateTime.now().minusMinutes(10));

		RefreshTokenService spyService = Mockito.spy(refreshTokenService);
		doNothing().when(spyService).updateRefreshToken(eq(token.getToken()), eq(true));

		UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> {
			spyService.verifyRefreshToken(token);
		});

		verify(spyService, times(1)).updateRefreshToken(eq(token.getToken()), eq(true));
		assertEquals("Invalid Refresh Token.", exception.getMessage());
	}
	
	
	@Test
	void testFindRefreshToken_ReturnsCorrectToken() {
		RefreshToken expectedToken = new RefreshToken();
		expectedToken.setToken(HASHED_TOKEN);
		Mockito.when(GeneralUtility.hashWithSHA256(PLAIN_TOKEN)).thenReturn(HASHED_TOKEN);

		Mockito.when(refreshTokenRepository.findByToken(HASHED_TOKEN)).thenReturn(expectedToken);

		RefreshToken actualToken = refreshTokenService.findRefreshToken(PLAIN_TOKEN);

		assertNotNull(actualToken);
		assertEquals(HASHED_TOKEN, actualToken.getToken());

	}

	
	@Test
	void testGenerateOpaqueRefreshToken() {
		String token = refreshTokenService.generateOpaqueRefreshToken();

		assertNotNull(token);
		assertFalse(token.isEmpty());

		assertTrue(token.matches("^[A-Za-z0-9_-]+$"));

		int minExpectedLength = 43;
		assertTrue(token.length() >= minExpectedLength);
	}

}
