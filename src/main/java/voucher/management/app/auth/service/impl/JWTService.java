package voucher.management.app.auth.service.impl;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.InvalidKeyException;
import voucher.management.app.auth.configuration.JWTConfig;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuditLogInvalidUser;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
public class JWTService {
	
	@Value("${pentest.enable}")
	private String pentestEnable;


	@Autowired
	private JWTConfig jwtConfig;
	
	@Autowired
	ApplicationContext context;

	public String generateToken(String userName, String userEmail, String userID, Boolean isRefreshToken)
			throws InvalidKeyException, Exception {
		
		
		long tokenValidDuration;
	    
	    // Check if pentest is enabled and adjust token validity to 30 minutes
	    if (pentestEnable.equalsIgnoreCase("true")) {
	        tokenValidDuration = System.currentTimeMillis() + 30 * 60 * 1000;  
	    } // 24 hours for refresh token // 15 minutes for normal token
	    else {
	        tokenValidDuration = System.currentTimeMillis() + (isRefreshToken ? 24 * 60 * 60 * 1000 : 15 * 60 * 1000);
	    }

		
		Map<String, Object> claims = new HashMap<>();
		claims.put("userEmail", userEmail);
		claims.put("userName", userName);
		return Jwts.builder().claims().add(claims).subject(userID).issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(tokenValidDuration)).and().signWith(loadPrivateKey(), Jwts.SIG.RS256).compact();
	}

	private PrivateKey loadPrivateKey() throws Exception {
		byte[] decoded = Base64.getDecoder().decode(jwtConfig.getJWTPrivateKey());
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}

	public PublicKey loadPublicKey() throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(jwtConfig.getJWTPubliceKey());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
	}

	public String extractUserID(String token) throws JwtException, IllegalArgumentException, Exception {
		// TODO Auto-generated method stub
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimResolver)
			throws JwtException, IllegalArgumentException, Exception {
		final Claims cliams = extractAllClaims(token);
		return claimResolver.apply(cliams);
	}

	public Claims extractAllClaims(String token) throws JwtException, IllegalArgumentException, Exception {
		return Jwts.parser().verifyWith(loadPublicKey()).build().parseSignedClaims(token).getPayload();
	}

	public boolean validateToken(String token, UserDetails userDetails)
			throws JwtException, IllegalArgumentException, Exception {
		Claims claims = extractAllClaims(token);
		String userEmail = claims.get("userEmail", String.class);
		return (userEmail.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	public boolean isTokenExpired(String token) throws JwtException, IllegalArgumentException, Exception {
		return extractExpiration(token).before(new Date());
	}

	public Date extractExpiration(String token) throws JwtException, IllegalArgumentException, Exception {
		return extractClaim(token, Claims::getExpiration);
	}
	
	
	public UserDetails getUserDetail(String token) throws JwtException, IllegalArgumentException, Exception {
		String userID = extractUserID(token);
		User user = context.getBean(UserService.class).findActiveUserByID(userID);
		UserDetails userDetails = org.springframework.security.core.userdetails.User
				.withUsername(user.getEmail()).password(user.getPassword()).roles(user.getRole().toString())
				.build();
		return userDetails;
	}
    
	public String retrieveUserID(String token) throws JwtException, IllegalArgumentException, Exception {
		try {
			return extractClaim(token, Claims::getSubject);
		} catch (ExpiredJwtException e) {
			return e.getClaims().getSubject();
		} catch (Exception e) {
			return AuditLogInvalidUser.INVALID_USER_ID.toString();
		}
	}
	
	public String retrieveUserName(String token) throws JwtException, IllegalArgumentException, Exception {
		try {
			Claims claims = extractAllClaims(token);
			String userName = claims.get("userName", String.class);
			return userName;
		} catch (ExpiredJwtException e) {
			return e.getClaims().get("userName", String.class);
		} catch (Exception e) {
			return AuditLogInvalidUser.INVALID_USER_NAME.toString();
		}
	}


}
