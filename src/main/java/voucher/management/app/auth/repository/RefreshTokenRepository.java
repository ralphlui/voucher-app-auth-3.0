package voucher.management.app.auth.repository;

import java.time.LocalDateTime;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import voucher.management.app.auth.entity.RefreshToken;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

	RefreshToken save(RefreshToken refreshToken);
	
	RefreshToken findByToken(String token);

	@Modifying
	@Transactional
	@Query("UPDATE RefreshToken r SET r.revoked = ?1, r.lastUpdatedDate = ?2 WHERE r.token = ?3")
	int updateRefreshToken(Boolean revoked, LocalDateTime lastUpdatedDate, String token);
}
