package voucher.management.app.auth.service;

import io.jsonwebtoken.JwtException;

public interface IRefreshTokenService {

	void saveRefreshToken(String userID, String token) throws JwtException, IllegalArgumentException, Exception;
	
	Boolean verifyRefreshToken(String refreshToken) throws JwtException, IllegalArgumentException, Exception;
	
	void updateRefreshToken(String token, Boolean revoked);
}
