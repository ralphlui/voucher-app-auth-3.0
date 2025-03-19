package voucher.management.app.auth.jwt;

import io.jsonwebtoken.*;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import voucher.management.app.auth.enums.AuditLogInvalidUser;
import voucher.management.app.auth.enums.AuditLogResponseStatus;
import voucher.management.app.auth.service.impl.AuditLogService;
import voucher.management.app.auth.service.impl.JWTService;
import voucher.management.app.auth.service.impl.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {

	@Autowired
	private JWTService jwtService;

	@Autowired
	ApplicationContext context;
	
	@Autowired
	private AuditLogService auditLogService;
	
	@Autowired
	@Lazy
	private UserService userService;
	
	private String userID;
	private String userName;
	private String apiEndpoint;
	private String httpMethod;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		String authHeader = request.getHeader("Authorization");
	    apiEndpoint = request.getRequestURI();
	    httpMethod = request.getMethod();
	    userID = AuditLogInvalidUser.InvalidUserID.toString();
	    userName = AuditLogInvalidUser.InvalidUserName.toString();
	    String requestURI = request.getRequestURI(); 

		if (requestURI.contains("google/userinfo") || requestURI.contains("/api/users/login") || authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		String jwtToken = authHeader.substring(7); // Remove "Bearer " prefix
	

		if (SecurityContextHolder.getContext().getAuthentication() == null && !jwtToken.isEmpty()) {
			try {
		    userID = jwtService.retrieveUserID(jwtToken);	
		    userName = jwtService.retrieveUserName(jwtToken);
			UserDetails userDetails = jwtService.getUserDetail(jwtToken);
				if (jwtService.validateToken(jwtToken, userDetails)) {
					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
							userDetails, null, userDetails.getAuthorities());
					authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			} catch (ExpiredJwtException e) {
				handleException(response, "JWT token is expired", HttpServletResponse.SC_UNAUTHORIZED);
				return;
			} catch (MalformedJwtException e) {
				handleException(response, "Invalid JWT token", HttpServletResponse.SC_UNAUTHORIZED);
				return;
			} catch (SecurityException e) {
				handleException(response, "JWT signature is invalid", HttpServletResponse.SC_UNAUTHORIZED);
				return;
			} catch (Exception e) {
				handleException(response, e.getMessage(), HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
		}

		filterChain.doFilter(request, response);
	}
	
	private void handleException(HttpServletResponse response, String message, int status) throws IOException {
		TokenErrorResponse.sendErrorResponse(response, message, status, "UnAuthorized");
		auditLogService.sendAuditLogToSqs(Integer.toString(status), userID, userName, "", message, apiEndpoint, AuditLogResponseStatus.FAILED.toString(), httpMethod, message);
	}
}