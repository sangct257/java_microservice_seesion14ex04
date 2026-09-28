package springbootrestapi.identityservice.security.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import springbootrestapi.identityservice.dto.respose.ApiResonse;
import springbootrestapi.identityservice.dto.respose.ErrorResponse;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ApiResonse<Object> apiResponse = new ApiResonse<>(
                false,
                "Yêu cầu xác thực thất bại: Token không hợp lệ hoặc đã hết hạn",
                null,
                ErrorResponse.builder()
                        .timestamp(LocalDateTime.now())
                        .error(Map.of("message", authException.getMessage()))
                        .path(request.getRequestURI())
                        .build(),
                HttpStatus.UNAUTHORIZED
        );

        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}