package voucher.management.app.auth.service.impl;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.amazonaws.services.simpleemail.AmazonSimpleEmailService;

import lombok.RequiredArgsConstructor;

import org.springframework.data.domain.Page;

import voucher.management.app.auth.configuration.AWSConfig;
import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;
import voucher.management.app.auth.exception.UserNotFoundException;
import voucher.management.app.auth.repository.UserRepository;
import voucher.management.app.auth.service.IUserService;
import voucher.management.app.auth.utility.AmazonSES;
import voucher.management.app.auth.utility.DTOMapper;
import voucher.management.app.auth.utility.EncryptionUtils;

@Service
@RequiredArgsConstructor
public class UserService implements IUserService  {
	
	private static final Logger logger = LoggerFactory.getLogger(UserService.class);

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final EncryptionUtils encryptionUtils;
	private final AWSConfig awsConfig;
	
	@Value("${frontend.url}")
	private String frontEndUrl;
	

	@Override
	public Map<Long, List<UserDTO>> findActiveUsers(Pageable pageable) {
		Map<Long, List<UserDTO>> result = new HashMap<>();
		List<UserDTO> userDTOList = new ArrayList<>();
		try {
			Page<User> userPages = userRepository.findActiveUserList(true, true, pageable);
			long totalRecord = userPages.getTotalElements();
			if (totalRecord > 0) {
				logger.info("Active user list is found.");
				for (User user : userPages.getContent()) {
					UserDTO userDTO = DTOMapper.toUserDTO(user);
					userDTOList.add(userDTO);
				}
			}
			result.put(totalRecord, userDTOList);
			return result;

		} catch (Exception ex) {
			logger.error("findByIsActiveTrue exception...", ex);
			throw ex;

		}
	}

	@Override
	public UserDTO createUser(UserRequest userReq) throws Exception {
		try {
			User user = new User();
			user.setEmail(userReq.getEmail());
			user.setUsername(userReq.getUsername());
			String encodedPassword = passwordEncoder.encode(userReq.getPassword());
			user.setPassword(encodedPassword);
			
			
			if(userReq.getAuthProvider().equals(AuthProvider.GOOGLE)) {
				user.setVerified(true);
				user.setAuthProvider(AuthProvider.GOOGLE);
				user.setVerificationCode("");
			}else {
			user.setVerified(false);
			user.setAuthProvider(AuthProvider.NATIVE);
			String code = UUID.randomUUID().toString();
			
			user.setVerificationCode(code);
			}
			user.setActive(true);
			user.setRole(userReq.getRole());
			
			user.setCreatedDate(LocalDateTime.now());
			 
			logger.info("Create User...");
			User createdUser = userRepository.save(user);
			
			if(!userReq.getAuthProvider().equals(AuthProvider.GOOGLE)) {
			if (createdUser == null) {
				throw new Exception("User registration is not successful");
			}
			logger.info("User registration is successful.");
			sendVerificationEmail(createdUser);
			}

			UserDTO userDTO = DTOMapper.toUserDTO(createdUser);
			return userDTO;

		} catch (Exception e) {
			logger.error("Error occurred while creating user", e);
			e.printStackTrace();
			throw e;

		}
	}
	
	
	@Override
	public User findByEmail(String email) {

		return userRepository.findByEmail(email);
	}
	
	
	@Override
	public User findByUserId(String userId) {

		try {
			User user = userRepository.findByUserId(userId);
			return user;
		} catch (Exception e) {
			throw e;
		}
		
	}


	@Override
	public UserDTO loginUser(String email, String password) {
		try {
			User user = userRepository.findByEmailAndStatus(email, true, true);
			if (user != null && passwordEncoder.matches(password, user.getPassword())) {
				logger.info("User login is successful.");
				return DTOMapper.toUserDTO(user);
			}
			logger.error("User login is not successful.");
			throw new UserNotFoundException("Invalid Credentials");
		} catch (Exception e) {
			logger.error("Error occurred while validating user login", e);
			e.printStackTrace();
			throw e;
		}
	}

	@Override
	public UserDTO verifyUser(String verificationCode) throws Exception {
		String decodedVerificationCode = encryptionUtils.decrypt(verificationCode);
		User user = userRepository.findByVerificationCode(decodedVerificationCode, false, true);
		if (user == null) {
			logger.error("Vefriy user failed: Verfiy Id is invalid or already verified.");
			throw new UserNotFoundException("Vefriy user failed: Verfiy Id is invalid or already verified.");
		}
		user.setVerified(true);
		user.setUpdatedDate(LocalDateTime.now());
		User verifiedUser = userRepository.save(user);
		UserDTO userDTO = DTOMapper.toUserDTO(verifiedUser);
		
		if (userDTO == null) {
			logger.error("Vefriy user failed: Verfiy Id is invalid or already verified.");
			throw new UserNotFoundException("Vefriy user failed: Verify Id is invalid or already verified.");
		}
		logger.info("User verification is successful.");
		return userDTO;
	}

	@Override
	public User findByEmailAndStatus(String email, boolean isActive, boolean isVerified) {

		return userRepository.findByEmailAndStatus(email, isActive, isVerified);
	}
	
	public User findByUserIdAndStatus(String userId, boolean isActive, boolean isVerified) {

		return userRepository.findByUserIdAndStatus(userId, isActive, isVerified);
	}
	
	
	
	@Override
	public UserDTO update(UserRequest userRequest) {
		try {
		
			User dbUser = findByUserId(userRequest.getUserId());
			if (dbUser == null) {
				throw new UserNotFoundException("User not found.");
			}
			dbUser.setUsername(userRequest.getUsername());
			dbUser.setPassword(passwordEncoder.encode(userRequest.getPassword()));
			dbUser.setActive(userRequest.getActive());
			dbUser.setUpdatedDate(LocalDateTime.now());
			logger.info("Update User...");
			User updateUser = userRepository.save(dbUser);
			logger.info("User update is successful");
			UserDTO updateUserDTO = DTOMapper.toUserDTO(updateUser);
			return updateUserDTO;
		} catch (Exception e) {
			logger.error("Error occurred while user updating", e);
			e.printStackTrace();
			throw e;
		}

	}
	
	public void sendVerificationEmail(User user) {

		try {

			AmazonSimpleEmailService client = awsConfig.sesClient();
			String from = awsConfig.getEmailFrom().trim();
			String clientURL = frontEndUrl;

			String to = user.getEmail();

			String verificationCode = encryptionUtils.encrypt(user.getVerificationCode());


			String verifyURL = clientURL + "/verification/" + verificationCode.trim();
			logger.info("verifyURL... {}", verifyURL);

			String subject = "Please verify your registration";
			String body = "Dear [[name]],<br><br>" + "Thank you for choosing our service.<br>"
					+ "To complete your registration, please click the link below to verify :<br>"
					+ "<h3><a href=\"[[URL]]\" target=\"_self\">VERIFY</a></h3>" + "Thank you" + "<br><br>"
					+ "<i>(This is an auto-generated email, please do not reply)</i>";

			body = body.replace("[[name]]", user.getUsername());

			body = body.replace("[[URL]]", verifyURL);

			AmazonSES.sendEmail(client, from, Arrays.asList(to), subject, body);
		} catch (Exception e) {
			logger.error("Error occurred while sendVerificationEmail", e);
			e.printStackTrace();
		}
	}

	@Override
	public UserDTO resetPassword(String userId, String password) {
		try {
			User dbUser = findByUserIdAndStatus(userId, true, true);
			if (dbUser == null) {
				logger.error("Reset Password failed.");
				throw new UserNotFoundException(
						"Reset Password failed: Unable to find the user with this user Id :" + userId);
			}

			dbUser.setPassword(passwordEncoder.encode(password));
			User updatedUser = userRepository.save(dbUser);
			logger.info("Reset Password is successful.");
			UserDTO updateUserDTO = DTOMapper.toUserDTO(updatedUser);
			return updateUserDTO;

		} catch (Exception e) {
			logger.error("Error occurred while validateUserLogin", e);
			e.printStackTrace();
			throw e;
		}
	}
	
	@Override
	public UserDTO checkSpecificActiveUser(String userId) {
		try {
			User user = findByUserIdAndStatus(userId, true, true);
			if (user == null) {
				logger.error("Active user is not found.");
				throw new UserNotFoundException("This user is not an active user");
			}
			logger.info("Active user is found.");
			return DTOMapper.toUserDTO(user);
			
		} catch (Exception e) {
			logger.error("Error occurred while checking specific active User, " + e.toString());
			e.printStackTrace();
			throw e;
		}
	}


	@Override
	public UserDTO updateRoleByUser(String userId, RoleType role) {
		try {
			User dbUser = findByUserId(userId);
			if (dbUser == null) {
				logger.error("user by this updated role is not found.");
				throw new UserNotFoundException("User not found.");
			}
			
			dbUser.setRole(role);

			dbUser.setUpdatedDate(LocalDateTime.now());

			User updateUser = userRepository.save(dbUser);
			logger.info("Role update is successful");
			UserDTO updateUserDTO = DTOMapper.toUserDTO(updateUser);
			logger.info("Update Role: {}", updateUserDTO.getRole());
			return updateUserDTO;

		} catch (Exception e) {
		     
		    logger.error("Error occurred while updating user role. Error message: {}", e.getMessage(), e);		    
		    throw new RuntimeException("Failed to update user role. Please check the logs for details.", e);

		}

	}

	@Override
	public UserDTO checkSpecificActiveUserByEmail(String email) {
		try {
			User user = findByEmailAndStatus(email, true, true);
			if (user == null) {
				logger.error("Active user is not found.");
				throw new UserNotFoundException("This user is not an active user");
			}
			logger.info("Active user is found.");
			return DTOMapper.toUserDTO(user);
			
		} catch (Exception e) {

		    logger.error("Error occurred while checking specific active user by email: {}", e.getMessage(), e);		     
		    throw e;

		}
		

	}
	
	@Override
	public User findActiveUserByID(String userId) {
		try {
			User user = findByUserIdAndStatus(userId, true, true);
			if (user == null) {
				logger.error("Active user is not found.");
				throw new UserNotFoundException("This user is not an active or verified user");
			}
			logger.info("Active user is found.");
			return user;
			
		} catch (Exception e) {
			logger.error("Error occurred while checking specific active User", e);
			e.printStackTrace();
			throw e;
		}
	}

}

