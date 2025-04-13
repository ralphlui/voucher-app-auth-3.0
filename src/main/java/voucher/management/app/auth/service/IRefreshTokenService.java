package voucher.management.app.auth.service;

import io.jsonwebtoken.JwtException;
import voucher.management.app.auth.entity.RefreshToken;

public interface IRefreshTokenService {

	void saveRefreshToken(String userID, String token) throws JwtException, IllegalArgumentException, Exception;
	
	Boolean verifyRefreshToken(RefreshToken refreshToken) throws JwtException, IllegalArgumentException, Exception;
	
	void updateRefreshToken(String token, Boolean revoked);
	
	String generateOpaqueRefreshToken();
	
	RefreshToken findRefreshToken(String refreshToken);
}
