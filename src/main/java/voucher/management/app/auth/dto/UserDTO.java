package voucher.management.app.auth.dto;

import lombok.Getter;
import lombok.Setter;
import voucher.management.app.auth.enums.AuthProvider;
import voucher.management.app.auth.enums.RoleType;

@Getter
@Setter
public class UserDTO {

	private String userID;
	private String email;
	private String username;
	private RoleType role;
	private boolean isActive;
	private boolean isVerified;
	private AuthProvider authProvider;
    public UserDTO(){
    }
    
}
