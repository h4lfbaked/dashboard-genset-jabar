from flask import Flask, render_template, request, jsonify, g
from Controller.LoginController import auth_bp
from ApiResponse import ApiResponse
from Config import app_config, auth_config

# Create Flask app
app = Flask(__name__)

# Initialize all configurations (CORS, Swagger, Auth)
app_config.init_app(app)

# Register Blueprint
app.register_blueprint(auth_bp)

@app.route('/')
def home():
    """
    Halaman utama aplikasi (tidak memerlukan autentikasi)
    """
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    """
    Endpoint untuk mengecek status API (tidak memerlukan autentikasi)
    ---
    tags:
      - System
    responses:
      200:
        description: Status API berhasil
        schema:
          $ref: '#/definitions/SuccessResponse'
    """
    status_data = {
        'api_status': 'running',
        'version': '1.0.0',
        'environment': 'development' if app.config['DEBUG'] else 'production',
        'authentication': 'Bearer Token Required (except /api/auth/login and /api/status)',
        'documentation': '/api/docs/',
        'endpoints_available': [
            '/api/status (public)',
            '/api/auth/login (public)',
            '/api/auth/logout (protected)',
            '/api/auth/validate (protected)',
            '/api/auth/session/info (protected)',
            '/api/auth/session/extend (protected)',
            '/api/auth/users (protected - admin only)',
            '/api/auth/sessions (protected - admin only)',
            '/api/auth/me (protected)',
            '/api/data (protected)',
            '/api/system/health (protected)'
        ],
        'config_info': app_config.get_config_info()
    }
    return ApiResponse.success(status_data, "Flask Genset API is running")

@app.route('/api/data', methods=['POST'])
def handle_data():
    """
    Endpoint untuk menangani data POST (memerlukan Bearer Token)
    ---
    tags:
      - System
    security:
      - Bearer: []
    parameters:
      - in: body
        name: data
        required: true
        schema:
          type: object
    responses:
      200:
        description: Data berhasil diproses
        schema:
          $ref: '#/definitions/SuccessResponse'
      401:
        description: Unauthorized
        schema:
          $ref: '#/definitions/ErrorResponse'
    """
    try:
        data = request.get_json()
        
        if not data:
            return ApiResponse.error("Request body diperlukan", 400, "NO_REQUEST_BODY")
        
        # Informasi user yang sedang login (dari Bearer Token)
        current_user = auth_config.get_current_user()
        
        # Proses data di sini
        processed_data = {
            'received_data': data,
            'processed_by': current_user['username'] if current_user else 'unknown',
            'user_role': current_user['role'] if current_user else 'unknown',
            'processed_at': request.environ.get('REQUEST_TIME', 'unknown'),
            'data_type': type(data).__name__,
            'data_size': len(str(data))
        }
        
        return ApiResponse.success(processed_data, "Data berhasil diterima dan diproses")
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam memproses data: {str(e)}", 500, "DATA_PROCESSING_ERROR")

@app.route('/api/system/health')
@auth_config.require_permission('read')
def system_health():
    """
    Endpoint untuk mengecek kesehatan sistem (memerlukan Bearer Token)
    ---
    tags:
      - System
    security:
      - Bearer: []
    responses:
      200:
        description: Status kesehatan sistem
        schema:
          $ref: '#/definitions/SuccessResponse'
      401:
        description: Unauthorized
        schema:
          $ref: '#/definitions/ErrorResponse'
      403:
        description: Insufficient permission
        schema:
          $ref: '#/definitions/ErrorResponse'
    """
    try:
        import psutil
        import time
        
        # System health data
        health_data = {
            'system': {
                'cpu_usage': psutil.cpu_percent(interval=1),
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'percent': psutil.virtual_memory().percent
                },
                'disk': {
                    'total': psutil.disk_usage('/').total,
                    'used': psutil.disk_usage('/').used,
                    'free': psutil.disk_usage('/').free,
                    'percent': psutil.disk_usage('/').percent
                }
            },
            'application': {
                'uptime': time.time(),
                'active_sessions': len(auth_config.login_service.active_sessions),
                'flask_debug': app.config['DEBUG']
            },
            'checked_by': auth_config.get_current_user()['username']
        }
        
        # Tentukan status berdasarkan metrics
        status = 'healthy'
        if health_data['system']['cpu_usage'] > 80:
            status = 'warning'
        if health_data['system']['memory']['percent'] > 85:
            status = 'critical'
        
        return ApiResponse.system_health_response(health_data, status)
        
    except ImportError:
        # Jika psutil tidak tersedia, return basic health
        health_data = {
            'application': {
                'status': 'running',
                'active_sessions': len(auth_config.login_service.active_sessions),
                'flask_debug': app.config['DEBUG']
            },
            'checked_by': auth_config.get_current_user()['username'],
            'note': 'Install psutil for detailed system metrics'
        }
        
        return ApiResponse.system_health_response(health_data, 'healthy')
        
    except Exception as e:
        return ApiResponse.error(f"Error dalam health check: {str(e)}", 500, "HEALTH_CHECK_ERROR")

@app.route('/user/<string:username>')
def user_profile(username):
    """
    Halaman profil pengguna (memerlukan Bearer Token)
    ---
    tags:
      - User Management
    security:
      - Bearer: []
    parameters:
      - in: path
        name: username
        type: string
        required: true
    responses:
      200:
        description: Profil pengguna
      401:
        description: Unauthorized
    """
    current_user = auth_config.get_current_user()
    if not current_user:
        return ApiResponse.unauthorized("Bearer Token diperlukan untuk mengakses profil")
    
    return f"<h1>Profil Pengguna: {username}</h1><p>Diakses oleh: {current_user['username']} ({current_user['role']})</p>"

@app.errorhandler(404)
def not_found(error):
    """
    Handler untuk error 404
    """
    return ApiResponse.not_found("Halaman tidak ditemukan")

@app.errorhandler(500)
def internal_error(error):
    """
    Handler untuk error 500
    """
    return ApiResponse.internal_server_error("Terjadi kesalahan internal server")

@app.errorhandler(400)
def bad_request(error):
    """
    Handler untuk error 400
    """
    return ApiResponse.error("Bad request", 400, "BAD_REQUEST")

@app.errorhandler(401)
def unauthorized(error):
    """
    Handler untuk error 401
    """
    return ApiResponse.unauthorized("Unauthorized access")

@app.errorhandler(403)
def forbidden(error):
    """
    Handler untuk error 403
    """
    return ApiResponse.forbidden("Access forbidden")

@app.errorhandler(405)
def method_not_allowed(error):
    """
    Handler untuk error 405
    """
    return ApiResponse.error("Method not allowed", 405, "METHOD_NOT_ALLOWED")

if __name__ == '__main__':
    # Menjalankan aplikasi Flask
    print("Starting Flask application...")
    print("Access the application at: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)