from flask import Blueprint, request, jsonify
from functools import wraps
from Service.LoginService import LoginService
from ApiResponse import ApiResponse

# Create Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Initialize LoginService
login_service = LoginService()

def require_session(f):
    """
    Decorator untuk memvalidasi session pada endpoint yang memerlukan autentikasi
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Ambil session token dari header Authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return ApiResponse.unauthorized("Authorization header diperlukan")
        
        # Extract token (format: "Bearer <token>")
        try:
            token = auth_header.split(' ')[1] if auth_header.startswith('Bearer ') else auth_header
        except IndexError:
            return ApiResponse.unauthorized("Format Authorization header tidak valid")
        
        # Validasi session
        validation_response = login_service.validate_session(token)
        if not validation_response[0].json['success']:
            return validation_response
        
        # Simpan session data ke request context
        request.session_data = validation_response[0].json['data']
        return f(*args, **kwargs)
    
    return decorated_function

def require_permission(permission):
    """
    Decorator untuk memeriksa permission berdasarkan role pengguna
    """
    def decorator(f):
        @wraps(f)
        @require_session
        def decorated_function(*args, **kwargs):
            user_role = request.session_data['role']
            
            # Check permission
            permission_response = login_service.check_user_permission(user_role, permission)
            if not permission_response[0].json['success']:
                return permission_response
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Endpoint untuk login pengguna
    ---
    tags:
      - Authentication
    summary: Login pengguna
    description: |
      Endpoint untuk autentikasi pengguna menggunakan username dan password.
      Endpoint ini **TIDAK** memerlukan Bearer Token.
      
      **Default Users:**
      - Username: `admin`, Password: `admin123` (Role: administrator)
      - Username: `operator`, Password: `operator123` (Role: operator) 
      - Username: `technician`, Password: `tech123` (Role: technician)
      - Username: `viewer`, Password: `viewer123` (Role: viewer)
    parameters:
      - in: body
        name: credentials
        required: true
        schema:
          $ref: '#/definitions/LoginRequest'
    responses:
      200:
        description: Login berhasil
        schema:
          $ref: '#/definitions/LoginResponse'
      400:
        description: Bad request - Input tidak valid
        schema:
          $ref: '#/definitions/ErrorResponse'
      401:
        description: Unauthorized - Kredensial salah
        schema:
          $ref: '#/definitions/ErrorResponse'
      403:
        description: Forbidden - Akun tidak aktif
        schema:
          $ref: '#/definitions/ErrorResponse'
      500:
        description: Internal server error
        schema:
          $ref: '#/definitions/ErrorResponse'
    """
    try:
        data = request.get_json()
        
        if not data:
            return ApiResponse.error("Request body diperlukan", 400, "NO_REQUEST_BODY")
        
        username = data.get('username')
        password = data.get('password')
        
        # Login menggunakan service
        return login_service.login(username, password)
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam login endpoint: {str(e)}", 500, "LOGIN_ENDPOINT_ERROR")

@auth_bp.route('/logout', methods=['POST'])
@require_session
def logout():
    """
    Endpoint untuk logout pengguna
    ---
    tags:
      - Authentication
    summary: Logout pengguna
    description: Logout pengguna dan hapus session aktif
    security:
      - Bearer: []
    responses:
      200:
        description: Logout berhasil
        schema:
          $ref: '#/definitions/SuccessResponse'
      401:
        description: Unauthorized - Bearer token tidak valid
        schema:
          $ref: '#/definitions/ErrorResponse'
      404:
        description: Session tidak ditemukan
        schema:
          $ref: '#/definitions/ErrorResponse'
    """
    try:
        # Ambil session token dari header
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1] if auth_header.startswith('Bearer ') else auth_header
        
        return login_service.logout(token)
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam logout endpoint: {str(e)}", 500, "LOGOUT_ENDPOINT_ERROR")

@auth_bp.route('/validate', methods=['GET'])
@require_session
def validate_session():
    """
    Endpoint untuk validasi session
    
    Header:
    Authorization: Bearer <session_token>
    """
    try:
        # Session sudah divalidasi oleh decorator @require_session
        session_data = request.session_data
        return ApiResponse.success(session_data, "Session valid")
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam validate endpoint: {str(e)}", 500, "VALIDATE_ENDPOINT_ERROR")

@auth_bp.route('/session/info', methods=['GET'])
@require_session
def get_session_info():
    """
    Endpoint untuk mendapatkan informasi session lengkap
    
    Header:
    Authorization: Bearer <session_token>
    """
    try:
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1] if auth_header.startswith('Bearer ') else auth_header
        
        return login_service.get_session_info(token)
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam session info endpoint: {str(e)}", 500, "SESSION_INFO_ENDPOINT_ERROR")

@auth_bp.route('/session/extend', methods=['POST'])
@require_session
def extend_session():
    """
    Endpoint untuk memperpanjang session
    
    Header:
    Authorization: Bearer <session_token>
    
    Body (optional):
    {
        "additional_hours": 2
    }
    """
    try:
        auth_header = request.headers.get('Authorization')
        token = auth_header.split(' ')[1] if auth_header.startswith('Bearer ') else auth_header
        
        data = request.get_json() or {}
        additional_hours = data.get('additional_hours', 2)  # Default 2 jam
        
        return login_service.extend_session(token, additional_hours)
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam extend session endpoint: {str(e)}", 500, "EXTEND_SESSION_ENDPOINT_ERROR")

@auth_bp.route('/user/<string:username>', methods=['GET'])
@require_permission('read')
def get_user_by_username(username):
    """
    Endpoint untuk mendapatkan data pengguna berdasarkan username
    
    Header:
    Authorization: Bearer <session_token>
    """
    try:
        return login_service.get_user_by_username(username)
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam get user endpoint: {str(e)}", 500, "GET_USER_ENDPOINT_ERROR")

@auth_bp.route('/users', methods=['GET'])
@require_permission('manage_users')
def get_all_users():
    """
    Endpoint untuk mendapatkan semua pengguna (hanya untuk admin)
    
    Header:
    Authorization: Bearer <session_token>
    """
    try:
        return login_service.get_all_users()
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam get all users endpoint: {str(e)}", 500, "GET_ALL_USERS_ENDPOINT_ERROR")

@auth_bp.route('/permission/check', methods=['POST'])
@require_session
def check_permission():
    """
    Endpoint untuk mengecek permission pengguna
    
    Header:
    Authorization: Bearer <session_token>
    
    Body:
    {
        "required_permission": "string"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return ApiResponse.error("Request body diperlukan", 400, "NO_REQUEST_BODY")
        
        required_permission = data.get('required_permission')
        if not required_permission:
            return ApiResponse.error("Required permission harus diisi", 400, "MISSING_PERMISSION")
        
        user_role = request.session_data['role']
        return login_service.check_user_permission(user_role, required_permission)
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam check permission endpoint: {str(e)}", 500, "CHECK_PERMISSION_ENDPOINT_ERROR")

@auth_bp.route('/sessions', methods=['GET'])
@require_permission('manage_users')
def get_active_sessions():
    """
    Endpoint untuk mendapatkan semua session aktif (hanya untuk admin)
    
    Header:
    Authorization: Bearer <session_token>
    """
    try:
        return login_service.get_active_sessions_count()
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam get sessions endpoint: {str(e)}", 500, "GET_SESSIONS_ENDPOINT_ERROR")

@auth_bp.route('/sessions/cleanup', methods=['POST'])
@require_permission('system_config')
def cleanup_expired_sessions():
    """
    Endpoint untuk membersihkan session yang expired (hanya untuk admin)
    
    Header:
    Authorization: Bearer <session_token>
    """
    try:
        return login_service.cleanup_expired_sessions()
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam cleanup sessions endpoint: {str(e)}", 500, "CLEANUP_SESSIONS_ENDPOINT_ERROR")

@auth_bp.route('/me', methods=['GET'])
@require_session
def get_current_user():
    """
    Endpoint untuk mendapatkan data pengguna yang sedang login
    ---
    tags:
      - User Management
    summary: Get current user info
    description: Mendapatkan informasi detail pengguna yang sedang login
    security:
      - Bearer: []
    responses:
      200:
        description: Data pengguna berhasil diambil
        schema:
          type: object
          properties:
            success:
              type: boolean
              example: true
            data:
              $ref: '#/definitions/UserData'
      401:
        description: Unauthorized - Bearer token tidak valid
        schema:
          $ref: '#/definitions/ErrorResponse'
    """
    try:
        username = request.session_data['username']
        return login_service.get_user_by_username(username)
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam get current user endpoint: {str(e)}", 500, "GET_CURRENT_USER_ENDPOINT_ERROR")

# Error handlers khusus untuk auth blueprint
@auth_bp.errorhandler(404)
def auth_not_found(error):
    """
    Handler untuk 404 di auth routes
    """
    return ApiResponse.not_found("Auth endpoint tidak ditemukan")

@auth_bp.errorhandler(405)
def auth_method_not_allowed(error):
    """
    Handler untuk 405 di auth routes  
    """
    return ApiResponse.error("Method tidak diizinkan", 405, "METHOD_NOT_ALLOWED")

@auth_bp.errorhandler(500)
def auth_internal_error(error):
    """
    Handler untuk 500 di auth routes
    """
    return ApiResponse.internal_server_error("Terjadi kesalahan internal pada auth service")