package voucher.management.app.auth.service;

import java.util.List;
import java.util.Map;

import org.springframework.data.domain.Pageable;

import voucher.management.app.auth.dto.UserDTO;
import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.entity.User;

public interface IUserService {
	Map<Long, List<UserDTO>> findActiveUsers(Pageable pageable);
	
	 UserDTO createUser(UserRequest userReq) throws Exception;
	 
	 User findByEmail(String email);
	 
	 UserDTO loginUser(String email, String password);
	 
	 UserDTO verifyUser(String verificationCode) throws Exception;
	 
	 User findByEmailAndStatus(String email, boolean isActive, boolean isVerified);
	 
	 UserDTO update(UserRequest userRequest);
	 
	 Map<Long, List<UserDTO>> findUsersByPreferences(String preferences, Pageable pageable);
	 
	 UserDTO resetPassword(String userId, String password);
	 
	 UserDTO checkSpecificActiveUser(String userId);
	 
	 UserDTO deletePreferencesByUser(String userId, List<String> preferences) throws Exception ;
	 
	 User findByUserId(String userId);
	 
	 UserDTO updatePreferencesByUser(String userId, List<String> preferences) throws Exception;
}
