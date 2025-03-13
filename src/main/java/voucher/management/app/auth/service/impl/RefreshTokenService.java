package voucher.management.app.auth.service.impl;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import voucher.management.app.auth.entity.RefreshToken;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.repository.RefreshTokenRepository;
import voucher.management.app.auth.service.IRefreshTokenService;

@Service
public class RefreshTokenService implements IRefreshTokenService {

	private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);

	@Autowired
	private JWTService jwtService;

	@Autowired
	private UserService userService;

	@Autowired
	private RefreshTokenRepository refreshTokenRepsitory;

	@Override
	public void saveRefreshToken(String userID, String token) throws Exception {

		try {
			String hashedToken = jwtService.hashWithSHA256(token);
			
			User user = userService.findByUserId(userID);
			Date expiredDate = jwtService.extractExpiration(token);
			LocalDateTime localExpiredDateTime = expiredDate.toInstant()
                    .atZone(ZoneId.systemDefault()) // Convert to system's default zone
                    .toLocalDateTime();

			
			RefreshToken refreshToken = new RefreshToken();
			refreshToken.setToken(hashedToken);
			refreshToken.setLastUpdatedDate(LocalDateTime.now());
			refreshToken.setUser(user);
			refreshToken.setExpiryDate(localExpiredDateTime);
			refreshTokenRepsitory.save(refreshToken);
			
		} catch (Exception e) {
			logger.error("Error occurred while saving refresh token, " + e.toString());
			e.printStackTrace();
			throw e;

		}
	}

	public void updateRefreshToken(String token, Boolean revoked) {

		try {
			 String hashedToken = jwtService.hashWithSHA256(token);
			 refreshTokenRepsitory.updateRefreshToken(revoked, LocalDateTime.now(), hashedToken);

		} catch (Exception e) {
			logger.error("Error occurred while updating refresh token, " + e.toString());
			e.printStackTrace();
			throw e;

		}
	}
	
	public Boolean verifyRefreshToken(String refreshToken) throws Exception {
		try {
			 String hashedToken = jwtService.hashWithSHA256(refreshToken);
			 RefreshToken savedRefreshToken = refreshTokenRepsitory.findByToken(hashedToken);
			if (savedRefreshToken == null || savedRefreshToken.isRevoked()) {
				throw new UserNotFoundException("Invalid Refresh Token.");
			}
			UserDetails userDetails = jwtService.getUserDetail(refreshToken);
			return jwtService.validateToken(refreshToken, userDetails);
			
		} catch (Exception e) {
			logger.error("Error occurred while verifying refresh token, " + e.toString());
			e.printStackTrace();
			throw e;
		}
	}
}
