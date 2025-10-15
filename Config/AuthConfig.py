from flask import Flask, request, g
from functools import wraps
from ApiResponse import ApiResponse
from Service.LoginService import LoginService
import os

class AuthConfig:
    """
    Konfigurasi autentikasi Bearer Token untuk semua endpoint
    """
    
    # Endpoint yang tidak memerlukan autentikasi
    EXCLUDED_ENDPOINTS = [
        '/api/auth/login',
        '/api/status',
        '/api/docs/',
        '/api/docs/apispec.json',
        '/flasgger_static/',
        '/',
        '/static/',
        '/favicon.ico'
    ]
    
    # Endpoint yang memerlukan autentikasi khusus
    PROTECTED_ENDPOINTS = [
        '/api/auth/',
        '/api/genset/',
        '/api/users/',
        '/api/system/',
        '/api/data'
    ]
    
    def __init__(self):
        self.login_service = LoginService()
    
    def init_auth(self, app: Flask):
        """
        Inisialisasi sistem autentikasi untuk Flask app
        
        Args:
            app: Flask application instance
        """
        
        @app.before_request
        def authenticate_request():
            """
            Middleware untuk mengecek autentikasi sebelum setiap request
            """
            # Skip authentication untuk endpoint yang dikecualikan
            if self._is_excluded_endpoint(request.path):
                return None
            
            # Skip untuk OPTIONS request (CORS preflight)
            if request.method == 'OPTIONS':
                return None
            
            # Extract Bearer Token
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return ApiResponse.unauthorized("Authorization header diperlukan")
            
            # Validate Bearer format
            if not auth_header.startswith('Bearer '):
                return ApiResponse.unauthorized("Format Authorization header tidak valid. Gunakan: Bearer <token>")
            
            try:
                # Extract token
                token = auth_header.split(' ')[1]
                
                # Validate session token
                validation_response = self.login_service.validate_session(token)
                
                if not validation_response[0].json['success']:
                    return validation_response
                
                # Store session data in Flask g object
                g.current_user = validation_response[0].json['data']
                g.session_token = token
                
            except IndexError:
                return ApiResponse.unauthorized("Token tidak valid dalam Authorization header")
            except Exception as e:
                return ApiResponse.error(f"Error dalam autentikasi: {str(e)}", 500, "AUTHENTICATION_ERROR")
        
        return app
    
    def _is_excluded_endpoint(self, path: str) -> bool:
        """
        Cek apakah endpoint dikecualikan dari autentikasi
        
        Args:
            path: Request path
            
        Returns:
            bool: True jika dikecualikan
        """
        # Exact match
        if path in self.EXCLUDED_ENDPOINTS:
            return True
        
        # Prefix match untuk static files dan swagger
        for excluded in self.EXCLUDED_ENDPOINTS:
            if excluded.endswith('/') and path.startswith(excluded):
                return True
        
        return False
    
    def require_permission(self, permission: str):
        """
        Decorator untuk memeriksa permission spesifik
        
        Args:
            permission: Permission yang dibutuhkan
            
        Returns:
            decorator function
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Cek apakah user sudah terautentikasi
                if not hasattr(g, 'current_user'):
                    return ApiResponse.unauthorized("Autentikasi diperlukan")
                
                user_role = g.current_user['role']
                
                # Check permission
                permission_response = self.login_service.check_user_permission(user_role, permission)
                
                if not permission_response[0].json['success']:
                    return permission_response
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    def require_role(self, allowed_roles: list):
        """
        Decorator untuk memeriksa role spesifik
        
        Args:
            allowed_roles: List role yang diizinkan
            
        Returns:
            decorator function
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Cek apakah user sudah terautentikasi
                if not hasattr(g, 'current_user'):
                    return ApiResponse.unauthorized("Autentikasi diperlukan")
                
                user_role = g.current_user['role']
                
                if user_role not in allowed_roles:
                    return ApiResponse.forbidden(f"Role '{user_role}' tidak diizinkan. Diperlukan salah satu dari: {', '.join(allowed_roles)}")
                
                return f(*args, **kwargs)
            
            return decorated_function
        return decorator
    
    @staticmethod
    def get_current_user():
        """
        Mendapatkan data user yang sedang login
        
        Returns:
            dict: Data user atau None
        """
        return getattr(g, 'current_user', None)
    
    @staticmethod
    def get_session_token():
        """
        Mendapatkan session token yang sedang aktif
        
        Returns:
            str: Session token atau None
        """
        return getattr(g, 'session_token', None)
    
    def add_excluded_endpoint(self, endpoint: str):
        """
        Menambahkan endpoint ke daftar yang dikecualikan dari autentikasi
        
        Args:
            endpoint: Path endpoint yang akan dikecualikan
        """
        if endpoint not in self.EXCLUDED_ENDPOINTS:
            self.EXCLUDED_ENDPOINTS.append(endpoint)
    
    def remove_excluded_endpoint(self, endpoint: str):
        """
        Menghapus endpoint dari daftar yang dikecualikan
        
        Args:
            endpoint: Path endpoint yang akan dihapus
        """
        if endpoint in self.EXCLUDED_ENDPOINTS:
            self.EXCLUDED_ENDPOINTS.remove(endpoint)
    
    def configure_jwt_secret(self, app: Flask, secret_key: str = None):
        """
        Konfigurasi JWT secret key
        
        Args:
            app: Flask application
            secret_key: Secret key untuk JWT (optional)
        """
        if secret_key:
            app.config['JWT_SECRET_KEY'] = secret_key
        else:
            # Generate random secret jika tidak disediakan
            app.config['JWT_SECRET_KEY'] = os.urandom(32).hex()
        
        # Additional JWT configurations
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False  # Token tidak expire otomatis
        app.config['JWT_ALGORITHM'] = 'HS256'
    
    def get_bearer_token_from_request(self) -> tuple:
        """
        Extract Bearer token dari request header
        
        Returns:
            tuple: (success: bool, token: str or error_message: str)
        """
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return False, "Authorization header tidak ditemukan"
        
        if not auth_header.startswith('Bearer '):
            return False, "Format Authorization header tidak valid"
        
        try:
            token = auth_header.split(' ')[1]
            return True, token
        except IndexError:
            return False, "Token tidak valid dalam Authorization header"


# Global instance untuk digunakan di seluruh aplikasi
auth_config = AuthConfig()