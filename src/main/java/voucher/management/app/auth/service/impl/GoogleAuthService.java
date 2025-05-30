package voucher.management.app.auth.service.impl;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;

import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.utility.DTOMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;
import java.util.Map;
import java.io.IOException;
import java.security.GeneralSecurityException;

@Service
public class GoogleAuthService {
	
	private static final Logger logger = LoggerFactory.getLogger(GoogleAuthService.class);

	@Value("${google.token.info.url}")
	public String googleTokenInfoUrl;

   
    private static String googleClientId= System.getenv("GOOGLE_CLIENT_ID");
     
	
	private final UserService userService;

	public GoogleAuthService(UserService userService) {
	    this.userService = userService;
	}
	
    
    public UserDTO verifyAndGetUserInfo(String idToken) throws GeneralSecurityException, IOException {
        
        String email = null;
        String name = null;
        UserDTO userDTO = new UserDTO();
        try {
        	
            // Verifying the ID Token
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken == null) {
                throw new SecurityException("Invalid ID Token");
            }

            
            String url = UriComponentsBuilder
                    .fromUriString(googleTokenInfoUrl.trim())
                    .queryParam("id_token", idToken)
                    .toUriString();
   
            RestTemplate restTemplate = new RestTemplate();
           
            Map<String, Object> val = restTemplate.getForObject(url, Map.class);
                       

            if (val != null) {
                email = (String) val.get("email");
                name = (String) val.get("name");
            }

            // Check if user exists in the system
             User user = userService.findByEmail(email);
            if (user != null) {
            	
            	 userDTO = DTOMapper.toUserDTO(user);
            	
            } else {
                // Create a new user with default role and store them
                UserRequest newUser = new UserRequest();
                newUser.setEmail(email);
                newUser.setPassword(email);
                newUser.setAuthProvider(AuthProvider.GOOGLE);
                newUser.setUsername(name);
                newUser.setRole(RoleType.UNDEFINED);
                newUser.setActive(true);

                userDTO = userService.createUser(newUser);

            }

        } catch (Exception e) {

            logger.error("Exception occurred: {} " , e.toString());
        }

        return  userDTO;
    }

}

