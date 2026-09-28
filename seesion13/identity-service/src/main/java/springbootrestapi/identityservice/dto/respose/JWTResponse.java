package springbootrestapi.identityservice.dto.respose;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class JWTResponse {
    private String username;
    private Boolean enabled;
    private Collection<? extends GrantedAuthority> authorities;
    private String accessToken;
    private String refreshToken;
    @Builder.Default
    private String type = "Bearer";
}
