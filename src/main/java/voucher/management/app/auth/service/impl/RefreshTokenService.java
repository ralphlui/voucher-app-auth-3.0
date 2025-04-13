package voucher.management.app.auth.service.impl;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import voucher.management.app.auth.entity.RefreshToken;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.repository.RefreshTokenRepository;
import voucher.management.app.auth.service.IRefreshTokenService;
import voucher.management.app.auth.utility.GeneralUtility;

@Service
@RequiredArgsConstructor
public class RefreshTokenService implements IRefreshTokenService {

	private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

	private final UserService userService;
	private final RefreshTokenRepository refreshTokenRepository;

	@Override
	public void saveRefreshToken(String userID, String token) throws JwtException, IllegalArgumentException, Exception {

		String hashedToken = GeneralUtility.hashWithSHA256(token);

		User user = userService.findByUserId(userID);
		LocalDateTime localExpiredDateTime = LocalDateTime.now().plusHours(24);
		RefreshToken refreshToken = new RefreshToken();
		refreshToken.setToken(hashedToken);
		refreshToken.setLastUpdatedDate(LocalDateTime.now());
		refreshToken.setUser(user);
		refreshToken.setExpiryDate(localExpiredDateTime);
		refreshTokenRepository.save(refreshToken);
	}

	@Override
	public void updateRefreshToken(String token, Boolean revoked) {

		try {
			String hashedToken = GeneralUtility.hashWithSHA256(token);
			refreshTokenRepository.updateRefreshToken(revoked, LocalDateTime.now(), hashedToken);

		} catch (Exception e) {
			logger.error("Error occurred while updating refresh token ", e);
			e.printStackTrace();
			throw new RuntimeException("Error updating refresh token", e);

		}
	}

	@Override
	public Boolean verifyRefreshToken(RefreshToken refreshToken)
			throws JwtException, IllegalArgumentException, Exception {

		boolean revoked = refreshToken.isRevoked();
		boolean expired = refreshToken.getExpiryDate().isBefore(LocalDateTime.now());

		if (revoked || expired) {
			if (expired && !revoked) {
				refreshTokenRepository.updateRefreshToken(true, LocalDateTime.now(), refreshToken.getToken());
			}
			throw new UserNotFoundException("Invalid Refresh Token.");
		}

		return true;
	}

	@Override
	public RefreshToken findRefreshToken(String refreshToken) {
		String hashedToken = GeneralUtility.hashWithSHA256(refreshToken);
		return refreshTokenRepository.findByToken(hashedToken);
	}
	
	
	@Override
	public String generateOpaqueRefreshToken() {
		SecureRandom secureRandom = new SecureRandom();
		byte[] tokenBytes = new byte[32];
		secureRandom.nextBytes(tokenBytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
	}
}
