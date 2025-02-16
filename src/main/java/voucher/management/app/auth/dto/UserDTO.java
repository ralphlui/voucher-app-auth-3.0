package voucher.management.app.auth.dto;

import java.util.List;

import lombok.Getter;
import lombok.Setter;
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
	private List<String> preferences;
    public UserDTO(){
    }
    
}
