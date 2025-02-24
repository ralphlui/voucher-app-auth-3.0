package voucher.management.app.auth.service;

public interface IRefreshTokenService {

	void saveRefreshToken(String userID, String token) throws Exception;
}
