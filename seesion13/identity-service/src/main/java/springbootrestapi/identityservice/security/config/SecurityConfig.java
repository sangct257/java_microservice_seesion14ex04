package springbootrestapi.identityservice.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import springbootrestapi.identityservice.security.exception.CustomAccessDeniedHandler;
import springbootrestapi.identityservice.security.exception.CustomAuthenticationEntryPoint;

@Configuration // Đánh dấu đây là lớp cấu hình (Configuration class) của Spring Context
@EnableWebSecurity // Kích hoạt các tính năng bảo mật web (Web Security) của Spring Security
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    /**
     * Khai báo Bean mã hóa mật khẩu.
     * Sử dụng thuật toán mã hóa băm BCrypt - chuẩn mã hóa an toàn nhất hiện nay cho password.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception{
        return authenticationConfiguration.getAuthenticationManager();
    }
    /**
     * Cấu hình chuỗi Filter kiểm soát tất cả các HTTP Request đi vào ứng dụng.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ObjectMapper objectMapper) throws Exception {
        http
                // 1. Tắt CSRF (Cross-Site Request Forgery)
                // Vì ứng dụng dùng REST API và JWT Stateless (không dùng Session Form trên giao diện) nên tắt CSRF.
                .csrf(AbstractHttpConfigurer::disable)

                // 2. Định hình cơ chế Session là STATELESS
                // Server sẽ KHÔNG lưu trữ Session của người dùng trong bộ nhớ.
                // Mọi request gửi lên phải tự định danh bằng Token.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // 3. Phân quyền các endpoint API
                .authorizeHttpRequests(authorize -> authorize
                        // Mở hoàn toàn (permitAll) cho các API bắt đầu bằng /api/auth/ (Đăng ký, Đăng nhập, Test token)
                        .requestMatchers("/api/auth/**").permitAll()
                        // Yêu cầu phải xác thực (đăng nhập/có token) đối với tất cả các request còn lại
                        .anyRequest().authenticated()
                )

                // Đăng ký Handler xử lý lỗi 401 & 403
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                // 4. Bật phương thức xác thực cơ bản HTTP Basic cho tiện việc test thử nghiệm
                .httpBasic(Customizer.withDefaults());

        // Xây dựng và trả về chuỗi lọc bảo mật hoàn chỉnh
        return http.build();
    }
}