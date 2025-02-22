package voucher.management.app.auth.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.repository.UserRepository;
import voucher.management.app.auth.utility.GeneralUtility;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

	@Autowired
	private UserService userService;

	private final String frontEndUrl;
	private final String emailFrom;
	private final String sqsUrl;

	@Autowired
	public OAuth2AuthenticationSuccessHandler(@Qualifier("getFrontEndUrl") String frontEndUrl,
			@Qualifier("getEmailFrom") String emailFrom, @Qualifier("getSQSUrl") String sqsUrl) {
		this.frontEndUrl = frontEndUrl;
		this.emailFrom = emailFrom;
		this.sqsUrl = sqsUrl;
	}

	public OAuth2AuthenticationSuccessHandler(String frontEndUrl) {
		this.frontEndUrl = frontEndUrl;
		this.emailFrom = "";
		this.sqsUrl = "";
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		try {
			OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
			OAuth2User principal = oauthToken.getPrincipal();

			String email = principal.getAttribute("email");
			String name = principal.getAttribute("name");
			logger.info("onAuthenticationSuccess: " + email);

			if (userExists(email)) {
				response.sendRedirect(frontEndUrl + "/dashboard");
			} else {

				// save in db with default role first and route role page
				UserRequest user = new UserRequest();
				user.setEmail(email);
				user.setPassword(email);
				user.setAuthProvider(AuthProvider.GOOGLE);
				user.setUsername(name);
				user.setRole(RoleType.CUSTOMER);
				user.setActive(true);
				user.setActive(true);
				UserDTO userDTO = userService.createUser(user);
				if (userDTO.getEmail().equals(email)) {
					logger.info(userDTO.getEmail() + " is created successfully");

					response.sendRedirect(frontEndUrl + "/choose-role");
				}
			}
		} catch (Exception e) {
			logger.error("Exception occurred in onAuthenticationSuccess :" + e.toString());
		}
	}

	public boolean userExists(String email) {
		// Check if user exists in DB
		try {
			if (!GeneralUtility.makeNotNull(email).equals("")) {
				User dbUser = userService.findByEmail(email);

				if (!GeneralUtility.makeNotNull(dbUser.getEmail()).equals("")) {
					return true;
				}

			}
		} catch (Exception e) {
			logger.error("Exception occurred in userExists :" + e.toString());
		}
		return false;

	}
}
