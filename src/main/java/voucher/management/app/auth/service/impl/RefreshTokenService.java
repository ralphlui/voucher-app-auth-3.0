package voucher.management.app.auth.service.impl;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
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

	private final JWTService jwtService;
	private final UserService userService;
	private final RefreshTokenRepository refreshTokenRepository;

	@Override
	public void saveRefreshToken(String userID, String token) throws JwtException, IllegalArgumentException, Exception {

		String hashedToken = GeneralUtility.hashWithSHA256(token);

		User user = userService.findByUserId(userID);
		Date expiredDate = jwtService.extractExpiration(token);
		LocalDateTime localExpiredDateTime = expiredDate.toInstant().atZone(ZoneId.systemDefault()) // Convert to
																									// system's default
																									// zone
				.toLocalDateTime();

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
			throw e;

		}
	}
	
	@Override
	public Boolean verifyRefreshToken(String refreshToken) throws JwtException, IllegalArgumentException, Exception {

		String hashedToken = GeneralUtility.hashWithSHA256(refreshToken);
		RefreshToken savedRefreshToken = refreshTokenRepository.findByToken(hashedToken);

		if (savedRefreshToken == null || savedRefreshToken.isRevoked()
				|| savedRefreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {

			Optional.ofNullable(savedRefreshToken).ifPresent(token -> updateRefreshToken(refreshToken, true));

			throw new UserNotFoundException("Invalid Refresh Token.");
		}
		UserDetails userDetails = jwtService.getUserDetail(refreshToken);
		return jwtService.validateToken(refreshToken, userDetails);
	}
}
