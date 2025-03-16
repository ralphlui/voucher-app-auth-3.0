package voucher.management.app.auth.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import jakarta.transaction.Transactional;
import voucher.management.app.auth.entity.RefreshToken;
import voucher.management.app.auth.entity.User;
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
	private RefreshTokenRepository refreshTokenRepsitory;

	@InjectMocks
	private RefreshTokenService refreshTokenService;

	@Mock
	private GeneralUtility generalUitlity;

	private String userId;
	private String token;
	private String hashedToken;
	private User user;
	private Date expiryDate;
	private LocalDateTime localExpiryDateTime;
	private Boolean revoked;

	@BeforeEach
	void setUp() throws Exception {
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
	void testUpdateRefreshToken_Success() {
		// Mock static utility method
		mockStatic(GeneralUtility.class);
		when(GeneralUtility.hashWithSHA256(token)).thenReturn(hashedToken);

		// Call the method
		assertDoesNotThrow(() -> refreshTokenService.updateRefreshToken(token, revoked));

		// Verify that the repository's update method was called with correct arguments
		verify(refreshTokenRepsitory, times(1)).updateRefreshToken(eq(revoked), any(LocalDateTime.class),
				eq(hashedToken));
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

		// Verify repository save method was called with the expected object
		verify(refreshTokenRepsitory, times(1)).save(any(RefreshToken.class));
	}

	@Test
	void testVerifyRefreshToken_Success() throws Exception {

		UserDetails userDetails = mock(UserDetails.class);
		RefreshToken savedRefreshToken = new RefreshToken();
		savedRefreshToken.setToken(hashedToken);
		savedRefreshToken.setRevoked(false);
		String refreshToken = "sample.jwt.token";
		hashedToken = "hashedSampleToken";

		when(refreshTokenRepsitory.findByToken(hashedToken)).thenReturn(savedRefreshToken);
		when(jwtService.getUserDetail(refreshToken)).thenReturn(userDetails);
		when(jwtService.validateToken(refreshToken, userDetails)).thenReturn(true);

		when(GeneralUtility.hashWithSHA256(refreshToken)).thenReturn(hashedToken);

		// Call the method and verify the result
		when(refreshTokenService.verifyRefreshToken(refreshToken)).thenReturn(true);

		verify(refreshTokenRepsitory, times(1)).findByToken(hashedToken);
		verify(jwtService, times(1)).getUserDetail(refreshToken);
	}

}
