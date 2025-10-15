from flask import jsonify
from datetime import datetime
from typing import Any, Optional, Dict, List, Union
import json

class ApiResponse:
    """
    Class untuk membungkus response API dengan format yang konsisten
    Menyediakan struktur standard untuk success, error, dan various response types
    """
    
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.version = "1.0.0"
    
    @staticmethod
    def success(data: Any = None, message: str = "Success", status_code: int = 200, **kwargs) -> tuple:
        """
        Response untuk operasi yang berhasil
        
        Args:
            data: Data yang akan dikembalikan
            message: Pesan sukses
            status_code: HTTP status code
            **kwargs: Additional fields
            
        Returns:
            tuple: (jsonify response, status_code)
        """
        response = {
            "success": True,
            "status_code": status_code,
            "message": message,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Tambahkan field tambahan jika ada
        response.update(kwargs)
        
        return jsonify(response), status_code
    
    @staticmethod
    def error(message: str = "An error occurred", status_code: int = 400, error_code: str = None, details: Any = None, **kwargs) -> tuple:
        """
        Response untuk error
        
        Args:
            message: Pesan error
            status_code: HTTP status code
            error_code: Code error internal
            details: Detail tambahan error
            **kwargs: Additional fields
            
        Returns:
            tuple: (jsonify response, status_code)
        """
        response = {
            "success": False,
            "status_code": status_code,
            "message": message,
            "error_code": error_code,
            "details": details,
            "data": None,
            "timestamp": datetime.now().isoformat()
        }
        
        # Tambahkan field tambahan jika ada
        response.update(kwargs)
        
        return jsonify(response), status_code
    
    @staticmethod
    def validation_error(errors: Dict[str, List[str]], message: str = "Validation failed") -> tuple:
        """
        Response khusus untuk validation error
        
        Args:
            errors: Dictionary berisi field dan error messages
            message: Pesan utama
            
        Returns:
            tuple: (jsonify response, 422)
        """
        response = {
            "success": False,
            "status_code": 422,
            "message": message,
            "error_code": "VALIDATION_ERROR",
            "validation_errors": errors,
            "data": None,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 422
    
    @staticmethod
    def unauthorized(message: str = "Unauthorized access") -> tuple:
        """
        Response untuk unauthorized access
        
        Args:
            message: Pesan unauthorized
            
        Returns:
            tuple: (jsonify response, 401)
        """
        response = {
            "success": False,
            "status_code": 401,
            "message": message,
            "error_code": "UNAUTHORIZED",
            "data": None,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 401
    
    @staticmethod
    def forbidden(message: str = "Access forbidden") -> tuple:
        """
        Response untuk forbidden access
        
        Args:
            message: Pesan forbidden
            
        Returns:
            tuple: (jsonify response, 403)
        """
        response = {
            "success": False,
            "status_code": 403,
            "message": message,
            "error_code": "FORBIDDEN",
            "data": None,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 403
    
    @staticmethod
    def not_found(message: str = "Resource not found") -> tuple:
        """
        Response untuk resource not found
        
        Args:
            message: Pesan not found
            
        Returns:
            tuple: (jsonify response, 404)
        """
        response = {
            "success": False,
            "status_code": 404,
            "message": message,
            "error_code": "NOT_FOUND",
            "data": None,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 404
    
    @staticmethod
    def internal_server_error(message: str = "Internal server error", error_details: str = None) -> tuple:
        """
        Response untuk internal server error
        
        Args:
            message: Pesan error
            error_details: Detail error untuk debugging
            
        Returns:
            tuple: (jsonify response, 500)
        """
        response = {
            "success": False,
            "status_code": 500,
            "message": message,
            "error_code": "INTERNAL_SERVER_ERROR",
            "error_details": error_details,
            "data": None,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 500
    
    @staticmethod
    def paginated_response(data: List[Any], page: int, per_page: int, total: int, message: str = "Success") -> tuple:
        """
        Response untuk data yang dipaginate
        
        Args:
            data: List data
            page: Halaman saat ini
            per_page: Jumlah item per halaman
            total: Total item
            message: Pesan response
            
        Returns:
            tuple: (jsonify response, 200)
        """
        total_pages = (total + per_page - 1) // per_page  # Ceiling division
        
        pagination_info = {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
            "next_page": page + 1 if page < total_pages else None,
            "prev_page": page - 1 if page > 1 else None
        }
        
        response = {
            "success": True,
            "status_code": 200,
            "message": message,
            "data": data,
            "pagination": pagination_info,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 200
    
    @staticmethod
    def login_success(user_data: Dict, session_token: str, expires_at: str) -> tuple:
        """
        Response khusus untuk login berhasil
        
        Args:
            user_data: Data user
            session_token: Session token
            expires_at: Waktu expire session
            
        Returns:
            tuple: (jsonify response, 200)
        """
        response = {
            "success": True,
            "status_code": 200,
            "message": "Login successful",
            "data": {
                "user": user_data,
                "session_token": session_token,
                "expires_at": expires_at
            },
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 200
    
    @staticmethod
    def logout_success(message: str = "Logout successful") -> tuple:
        """
        Response untuk logout berhasil
        
        Args:
            message: Pesan logout
            
        Returns:
            tuple: (jsonify response, 200)
        """
        response = {
            "success": True,
            "status_code": 200,
            "message": message,
            "data": None,
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 200
    
    @staticmethod
    def genset_status_response(genset_data: Dict, status: str = "online") -> tuple:
        """
        Response khusus untuk status genset
        
        Args:
            genset_data: Data genset
            status: Status genset (online/offline/maintenance)
            
        Returns:
            tuple: (jsonify response, 200)
        """
        response = {
            "success": True,
            "status_code": 200,
            "message": f"Genset status: {status}",
            "data": {
                "genset_info": genset_data,
                "system_status": status,
                "last_updated": datetime.now().isoformat()
            },
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 200
    
    @staticmethod
    def operation_response(operation: str, result: bool, details: Any = None, message: str = None) -> tuple:
        """
        Response untuk operasi genset (start, stop, maintenance, etc.)
        
        Args:
            operation: Jenis operasi
            result: Hasil operasi (True/False)
            details: Detail tambahan
            message: Custom message
            
        Returns:
            tuple: (jsonify response, status_code)
        """
        if message is None:
            message = f"Operation '{operation}' {'successful' if result else 'failed'}"
        
        status_code = 200 if result else 400
        
        response = {
            "success": result,
            "status_code": status_code,
            "message": message,
            "data": {
                "operation": operation,
                "result": result,
                "details": details,
                "executed_at": datetime.now().isoformat()
            },
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), status_code
    
    @staticmethod
    def system_health_response(health_data: Dict, status: str = "healthy") -> tuple:
        """
        Response untuk system health check
        
        Args:
            health_data: Data kesehatan sistem
            status: Status kesehatan (healthy/warning/critical)
            
        Returns:
            tuple: (jsonify response, 200)
        """
        response = {
            "success": True,
            "status_code": 200,
            "message": f"System health: {status}",
            "data": {
                "health_status": status,
                "health_data": health_data,
                "checked_at": datetime.now().isoformat()
            },
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        return jsonify(response), 200


class ApiResponseHelper:
    """
    Helper class untuk operasi tambahan pada ApiResponse
    """
    
    @staticmethod
    def format_error_details(exception: Exception) -> Dict:
        """
        Format exception menjadi error details
        
        Args:
            exception: Exception object
            
        Returns:
            Dict: Formatted error details
        """
        return {
            "type": type(exception).__name__,
            "message": str(exception),
            "timestamp": datetime.now().isoformat()
        }
    
    @staticmethod
    def validate_pagination_params(page: int, per_page: int) -> Optional[Dict]:
        """
        Validasi parameter pagination
        
        Args:
            page: Nomor halaman
            per_page: Jumlah item per halaman
            
        Returns:
            Dict: Error details jika ada error, None jika valid
        """
        errors = {}
        
        if page < 1:
            errors["page"] = ["Page must be greater than 0"]
        
        if per_page < 1:
            errors["per_page"] = ["Per page must be greater than 0"]
        
        if per_page > 100:
            errors["per_page"] = ["Per page cannot exceed 100"]
        
        return errors if errors else None
    
    @staticmethod
    def sanitize_response_data(data: Any) -> Any:
        """
        Sanitize data sebelum dijadikan response
        
        Args:
            data: Data yang akan disanitize
            
        Returns:
            Any: Data yang sudah disanitize
        """
        if isinstance(data, dict):
            # Remove sensitive keys
            sensitive_keys = ['password', 'password_hash', 'secret', 'token', 'api_key']
            sanitized = {}
            for key, value in data.items():
                if key.lower() not in sensitive_keys:
                    sanitized[key] = ApiResponseHelper.sanitize_response_data(value)
            return sanitized
        elif isinstance(data, list):
            return [ApiResponseHelper.sanitize_response_data(item) for item in data]
        else:
            return data