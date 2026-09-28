package springbootrestapi.identityservice.security.principal;

import lombok.*;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@AllArgsConstructor // Tự động sinh constructor chứa tất cả các tham số
@NoArgsConstructor  // Tự động sinh constructor không tham số
@Getter             // Tự động tạo các phương thức getter
@Setter             // Tự động tạo các phương thức setter
@Builder            // Cung cấp Pattern Builder để khởi tạo đối tượng nhanh gọn
public class CustomUserDetails implements UserDetails {
    private String id;
    // Các thuộc tính cơ bản của User lấy từ Database
    private String username;
    private String password;
    private Boolean enabled;

    // Danh sách các quyền (Roles/Permissions) của User dưới dạng danh sách các GrantedAuthority
    private Collection<? extends GrantedAuthority> authorities;

    /**
     * Trả về danh sách các quyền hạn được cấp cho người dùng này.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     * Trả về mật khẩu đã được mã hóa của người dùng.
     */
    @Override
    public @Nullable String getPassword() {
        return password;
    }

    /**
     * Trả về tên tài khoản dùng để đăng nhập.
     */
    @Override
    public String getUsername() {
        return username;
    }

    /**
     * Trạng thái tài khoản đã hết hạn hay chưa? (True: Còn hạn)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Trạng thái tài khoản có bị khóa hay không? (True: Không bị khóa)
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Trạng thái chứng thực (mật khẩu) có bị hết hạn hay chưa? (True: Còn hạn)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Trạng thái tài khoản có đang được kích hoạt hay không?
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }
}