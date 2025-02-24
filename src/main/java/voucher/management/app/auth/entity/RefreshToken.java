package voucher.management.app.auth.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

import org.hibernate.annotations.UuidGenerator;

@Entity
@Getter
@Setter
@AllArgsConstructor
public class RefreshToken {

	public RefreshToken() {
		super();
	}

	@Id
	@UuidGenerator(style = UuidGenerator.Style.AUTO)
	private String id;

	@ManyToOne
	@JoinColumn(name = "userId", nullable = false)
	private User user;

	@Column(unique = true, nullable = false)
	private String token;

	@Column(nullable = true, columnDefinition = "datetime")
	private LocalDateTime expiryDate;

	@Column(nullable = true, columnDefinition = "datetime")
	private LocalDateTime lastUpdatedDate;

	@Column(nullable = false)
	private boolean revoked = false;

	@Column(nullable = true, columnDefinition = "datetime")
	private LocalDateTime createdAt = LocalDateTime.now();

}
