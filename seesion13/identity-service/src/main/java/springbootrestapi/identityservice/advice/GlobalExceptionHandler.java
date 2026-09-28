package springbootrestapi.identityservice.advice;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import springbootrestapi.identityservice.dto.respose.ApiResonse;
import springbootrestapi.identityservice.dto.respose.ErrorResponse;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // 1. Lỗi Đăng nhập sai Username / Password
    @ExceptionHandler({BadCredentialsException.class, UsernameNotFoundException.class})
    public ResponseEntity<ApiResonse<Object>> handleBadCredentialsException(Exception e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "Tài khoản hoặc mật khẩu không chính xác",
                Map.of("message", e.getMessage()),
                request.getRequestURI()
        );
    }

    // 2. Lỗi Tài khoản bị khóa / vô hiệu hóa
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ApiResonse<Object>> handleDisabledException(DisabledException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "Tài khoản của bạn đã bị vô hiệu hóa",
                Map.of("message", e.getMessage()),
                request.getRequestURI()
        );
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ApiResonse<Object>> handleLockedException(LockedException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.UNAUTHORIZED,
                "Tài khoản của bạn đã bị khóa",
                Map.of("message", e.getMessage()),
                request.getRequestURI()
        );
    }

    // 3. Lỗi Không đủ quyền hạn (403 Forbidden) từ Method Security (@PreAuthorize)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResonse<Object>> handleAccessDeniedException(AccessDeniedException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.FORBIDDEN,
                "Bạn không có quyền thực hiện chức năng này",
                Map.of("message", e.getMessage()),
                request.getRequestURI()
        );
    }

    // 4. Lỗi Validation DTO đầu vào (@Valid)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResonse<Object>> handleValidationException(MethodArgumentNotValidException e, HttpServletRequest request) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError fieldError : e.getBindingResult().getFieldErrors()) {
            errors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Dữ liệu đầu vào không hợp lệ",
                errors,
                request.getRequestURI()
        );
    }

    // 5. Lỗi Logic nghiệp vụ chung (RuntimeException)
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResonse<Object>> handleRuntimeException(RuntimeException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                e.getMessage(),
                Map.of("message", e.getMessage()),
                request.getRequestURI()
        );
    }

    // 6. Tất cả các lỗi hệ thống không xác định khác (500 Internal Server Error)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResonse<Object>> handleGeneralException(Exception e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Đã có lỗi hệ thống xảy ra, vui lòng thử lại sau",
                Map.of("message", e.getMessage()),
                request.getRequestURI()
        );
    }

    // Lỗi JSON truyền lên sai cú pháp / rỗng
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResonse<Object>> handleHttpMessageNotReadable(
            HttpMessageNotReadableException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Định dạng dữ liệu JSON không hợp lệ hoặc body bị rỗng",
                Map.of("message", e.getMostSpecificCause().getMessage()),
                request.getRequestURI()
        );
    }

    // Lỗi gọi sai HTTP Method (ví dụ POST thay vì GET)
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResonse<Object>> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.METHOD_NOT_ALLOWED,
                "Phương thức " + e.getMethod() + " không được hỗ trợ cho endpoint này",
                Map.of("supportedMethods", e.getSupportedHttpMethods()),
                request.getRequestURI()
        );
    }

    // Lỗi truyền sai kiểu dữ liệu tham số trên URL (ví dụ: id kiểu Long nhưng truyền "abc")
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResonse<Object>> handleTypeMismatch(
            MethodArgumentTypeMismatchException e, HttpServletRequest request) {
        String error = String.format("Tham số '%s' phải thuộc kiểu '%s'", e.getName(), e.getRequiredType().getSimpleName());
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Tham số truy vấn không hợp lệ",
                Map.of("message", error),
                request.getRequestURI()
        );
    }

    // Lỗi thiếu Query Param bắt buộc
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiResonse<Object>> handleMissingParam(
            MissingServletRequestParameterException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.BAD_REQUEST,
                "Thiếu tham số bắt buộc: " + e.getParameterName(),
                Map.of("message", e.getMessage()),
                request.getRequestURI()
        );
    }

    // Lỗi vi phạm ràng buộc dữ liệu dưới Database (Unique Key, Foreign Key...)
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResonse<Object>> handleDataIntegrityViolation(
            DataIntegrityViolationException e, HttpServletRequest request) {
        return buildErrorResponse(
                HttpStatus.CONFLICT,
                "Xung đột dữ liệu hoặc vi phạm ràng buộc hệ thống",
                Map.of("message", e.getMostSpecificCause().getMessage()),
                request.getRequestURI()
        );
    }

    // Helper method dùng chung để tạo ResponseEntity
    private ResponseEntity<ApiResonse<Object>> buildErrorResponse(
            HttpStatus status,
            String message,
            Object errorDetail,
            String path) {

        ApiResonse<Object> response = new ApiResonse<>(
                false,
                message,
                null,
                ErrorResponse.builder()
                        .timestamp(LocalDateTime.now())
                        .error(errorDetail)
                        .path(path)
                        .build(),
                status
        );
        return new ResponseEntity<>(response, status);
    }
}