package voucher.management.app.auth.strategy.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import voucher.management.app.auth.dto.UserRequest;
import voucher.management.app.auth.dto.ValidationResult;
import voucher.management.app.auth.entity.User;
import voucher.management.app.auth.enums.AuditLogInvalidUser;
import voucher.management.app.auth.service.impl.UserService;
import voucher.management.app.auth.strategy.IAPIHelperValidationStrategy;

@Service
public class UserValidationStrategy implements IAPIHelperValidationStrategy<UserRequest> {

	@Autowired
	private UserService userService;

	private String auditLogInvalidUserId = AuditLogInvalidUser.InvalidUserID.toString();
	private String auditLogInvalidUserName = AuditLogInvalidUser.InvalidUserName.toString();

	@Override
	public ValidationResult validateCreation(UserRequest userRequest) {
		ValidationResult validationResult = new ValidationResult();

		if (userRequest.getEmail() == null || userRequest.getEmail().isEmpty()) {

			String userName = StringUtils.hasText(userRequest.getUsername()) ? userRequest.getUsername()
					: auditLogInvalidUserName;
			validationResult.setMessage("Email cannot be empty.");
			validationResult.setStatus(HttpStatus.BAD_REQUEST);
			validationResult.setValid(false);
			validationResult.setUserId(auditLogInvalidUserId);
			validationResult.setUserName(userName);
			return validationResult;
		}

		User dbUser = userService.findByEmail(userRequest.getEmail());
		if (dbUser != null) {
			validationResult.setMessage(userRequest.getEmail() + " is existed.");
			validationResult.setStatus(HttpStatus.BAD_REQUEST);
			validationResult.setValid(false);
			validationResult.setUserId(dbUser.getUserId());
			validationResult.setUserName(dbUser.getUsername());
			return validationResult;
		}

		validationResult.setValid(true);
		return validationResult;
	}

	@Override
	public ValidationResult validateObject(String email) {
		User user = userService.findByEmail(email);

		if (user == null) {
			return validateUserNotFound(auditLogInvalidUserId, auditLogInvalidUserName);
		}

		String userId = user.getUserId();
		String userName = user.getUsername();

		if (!user.isActive()) {
			return validateDeletedUser(userId, userName);
		}

		if (!user.isVerified()) {
			return validateUnVerifiedUser(userId, userName);
		}

		return validateValidUser(userId, userName);
	}

	@Override
	public ValidationResult validateUpdating(String userId) {
		ValidationResult validationResult = new ValidationResult();

		if (userId == null || userId.isEmpty()) {
			validationResult.setMessage("User ID cannot be empty.");
			validationResult.setStatus(HttpStatus.BAD_REQUEST);
			validationResult.setValid(false);
			validationResult.setUserId(auditLogInvalidUserId);
			validationResult.setUserName(auditLogInvalidUserName);
			return validationResult;
		}

		ValidationResult validationObjResult = validateObjectByUserId(userId);
		if (!validationObjResult.isValid()) {
			return validationObjResult;
		}

		validationResult.setValid(true);
		return validationResult;
	}

	@Override
	public ValidationResult validateObjectByUserId(String userId) {
		User user = userService.findByUserId(userId);

		if (user == null) {
			return validateUserNotFound(userId, auditLogInvalidUserName);
		}

		String userName = user.getUsername();

		if (!user.isActive()) {
			return validateDeletedUser(userId, userName);
		}

		if (!user.isVerified()) {
			return validateUnVerifiedUser(userId, userName);
		}

		return validateValidUser(userId, userName);
	}

	private ValidationResult validateUserNotFound(String userId, String userName) {

		ValidationResult validationResult = new ValidationResult();
		validationResult.setMessage("User account not found.");
		validationResult.setStatus(HttpStatus.NOT_FOUND);
		validationResult.setValid(false);
		validationResult.setUserName(userName);
		validationResult.setUserId(userId);
		return validationResult;

	}

	private ValidationResult validateDeletedUser(String userId, String userName) {

		ValidationResult validationResult = new ValidationResult();
		validationResult.setMessage("User account is deleted.");
		validationResult.setStatus(HttpStatus.FORBIDDEN);
		validationResult.setValid(false);
		validationResult.setUserName(userName);
		validationResult.setUserId(userId);
		return validationResult;

	}

	private ValidationResult validateUnVerifiedUser(String userId, String userName) {

		ValidationResult validationResult = new ValidationResult();
		validationResult.setMessage("Please verify the account first.");
		validationResult.setStatus(HttpStatus.UNAUTHORIZED);
		validationResult.setValid(false);
		validationResult.setUserName(userName);
		validationResult.setUserId(userId);
		return validationResult;

	}

	private ValidationResult validateValidUser(String userId, String userName) {

		ValidationResult validationResult = new ValidationResult();
		validationResult.setUserId(userId);
		validationResult.setUserName(userName);
		validationResult.setValid(true);
		return validationResult;
	}

}
