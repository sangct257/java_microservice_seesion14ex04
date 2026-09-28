package springbootrestapi.identityservice.security.principal;

import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import springbootrestapi.identityservice.entity.Role;
import springbootrestapi.identityservice.entity.User;
import springbootrestapi.identityservice.repository.UserRepository;

import java.util.Collection;
import java.util.List;

@Service // Đánh dấu lớp này thuộc tầng Service xử lý Logic
@AllArgsConstructor // Tự động Inject các thuộc tính final (như UserRepository) thông qua Constructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Phương thức ghi đè bắt buộc của UserDetailsService.
     * Tìm kiếm thông tin User trong Database dựa theo username nhập vào.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Truy vấn Database để lấy thông tin User. Nếu không tìm thấy thì quăng ra Exception
        User users = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Tài khoản không tồn tại"));

        // Chuyển đổi đối tượng User (Entity) từ Database thành đối tượng CustomUserDetails (Spring Security hiểu)
        return CustomUserDetails.builder()
                .id(users.getUserId())
                .username(users.getUsername())
                .password(users.getPassword())
                .enabled(users.getEnabled())
                .authorities(mapRoleToAuthorities(users.getRoles())) // Ánh xạ danh sách Role sang GrantedAuthority
                .build();
    }

    /**
     * Hàm phụ trợ (Helper method): Chuyển đổi danh sách các Role (Entity)
     * sang tập hợp các SimpleGrantedAuthority mà Spring Security chấp nhận.
     */
    private Collection<? extends GrantedAuthority> mapRoleToAuthorities(List<Role> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleName().toString()))
                .toList();
    }
}