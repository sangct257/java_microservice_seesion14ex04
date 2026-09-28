package springbootrestapi.identityservice.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "refresh_token_id")
    private Long refreshTokenId;
    private String username;
    @Column(name = "expiry_date")
    private Instant expiryDate;
    @Column(name = "refresh_token",nullable = false, unique = true)
    private String refreshToken;
    private Boolean invoke;
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
}
