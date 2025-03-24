package voucher.management.app.auth.dto;

import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;

public class UserRequest {

	private String email;
	private String userId;
	private String username;
	private String password;
	private Boolean active;
	private RoleType role;
	private String accountVerificationCode;
	
    private AuthProvider authProvider;
    
    private String otp;

	public UserRequest() {
		super();
	}
	
	public UserRequest(String email, String password) {
		super();
		this.email = email;
		this.password = password;
	}
	

	public UserRequest(String email, String password, String username, RoleType role, Boolean active) {
		super();
		
		this.email = email;
		this.password = password;
		this.username = username;
		this.role = role;
		this.active = active;
	}
	
	public UserRequest(String userId, String email, String password, String username, RoleType role, Boolean active) {
		super();
		
		this.password = password;
		this.username = username;
		this.role = role;
		this.active = active;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}


	public String getUsername() {
		return username;
	}


	public void setUsername(String username) {
		this.username = username;
	}


	public Boolean getActive() {
		return active;
	}


	public void setActive(Boolean active) {
		this.active = active;
	}


	public RoleType getRole() {
		return role;
	}


	public void setRole(RoleType role) {
		this.role = role;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public AuthProvider getAuthProvider() {
		return authProvider;
	}

	public void setAuthProvider(AuthProvider authProvider) {
		this.authProvider = authProvider;
	}

	public String getOtp() {
		return otp;
	}

	public void setOtp(String otp) {
		this.otp = otp;
	}

	public String getAccountVerificationCode() {
		return accountVerificationCode;
	}

	public void setAccountVerificationCode(String accountVerificationCode) {
		this.accountVerificationCode = accountVerificationCode;
	}
	
	
}
