package springbootrestapi.identityservice.dto.respose;

import lombok.*;
import springbootrestapi.identityservice.entity.Role;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponse {
    private String id;
    private String username;
    private List<Role> roles;
    private Boolean enabled;
}
