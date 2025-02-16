package voucher.management.app.auth.entity;

import java.time.LocalDateTime;

import org.hibernate.annotations.UuidGenerator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import voucher.management.app.auth.enums.RoleType;

@Entity
@Getter
@Setter
@AllArgsConstructor
public class User {
	public User() {
		super();
	}

	public User(String email, String username, String password, RoleType role, boolean isActive) {
		super();
		this.email = email;
		this.username = username;
		this.password = password;
		this.role = role;
		this.isActive = isActive;
	}

	@Id
	@UuidGenerator(style = UuidGenerator.Style.AUTO)
	private String userId;

	@Column(nullable = false, unique = true)
	private String email;

	@Column(nullable = false)
	private String username;

	@Column(nullable = false)
	private String password;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private RoleType role;

	@Column(nullable = false, columnDefinition = "datetime default now()")
	private LocalDateTime createdDate;

	@Column(nullable = true, columnDefinition = "datetime")
	private LocalDateTime updatedDate;

	@Column(nullable = false, columnDefinition = "boolean default true")
	private boolean isActive;

	@Column(nullable = true, columnDefinition = "datetime")
	private LocalDateTime lastLoginDate;

	
	@Column(nullable = false, columnDefinition = "varchar(255) default ''")
    private String verificationCode;
    
	@Column(nullable = false, columnDefinition = "boolean default false")
    private boolean isVerified;
	
	@Column(nullable = true, columnDefinition = "varchar(255)")
	private String preferences;
	
}

