package springbootrestapi.identityservice.security.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import springbootrestapi.identityservice.dto.respose.ApiResonse;
import springbootrestapi.identityservice.dto.respose.ErrorResponse;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ApiResonse<Object> apiResponse = new ApiResonse<>(
                false,
                "Bạn không có quyền truy cập vào tài nguyên này",
                null,
                ErrorResponse.builder()
                        .timestamp(LocalDateTime.now())
                        .error(Map.of("message", accessDeniedException.getMessage()))
                        .path(request.getRequestURI())
                        .build(),
                HttpStatus.FORBIDDEN
        );

        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}