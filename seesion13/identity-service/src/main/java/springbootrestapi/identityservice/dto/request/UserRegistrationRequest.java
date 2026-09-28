package springbootrestapi.identityservice.dto.request;

import lombok.*;
import springbootrestapi.identityservice.entity.Role;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserRegistrationRequest {
    private String username;
    private String password;
    private List<Role> roles;
    private Boolean enabled;
}
