from flask import Flask
import os
from .SwaggerConfig import SwaggerConfig
from .CorsConfig import CorsConfig
from .AuthConfig import AuthConfig, auth_config

class AppConfig:
    """
    Konfigurasi utama aplikasi Flask
    """
    
    def __init__(self):
        self.swagger_config = SwaggerConfig()
        self.cors_config = CorsConfig()
        self.auth_config = auth_config
    
    def init_app(self, app: Flask):
        """
        Inisialisasi semua konfigurasi untuk Flask app
        
        Args:
            app: Flask application instance
        """
        
        # 1. Basic Flask Configuration
        self._configure_flask(app)
        
        # 2. Initialize CORS (harus sebelum auth untuk handle preflight)
        if app.config.get('ENABLE_CORS', True):
            self.cors_config.init_cors(app)
            print("✅ CORS initialized")
        
        # 3. Initialize Authentication (global middleware)
        self.auth_config.init_auth(app)
        print("✅ Bearer Token Authentication initialized")
        
        # 4. Initialize Swagger (setelah auth untuk dokumentasi)
        if app.config.get('ENABLE_SWAGGER', True):
            self.swagger_config.init_swagger(app)
            print("✅ Swagger documentation initialized")
            print("📖 API Documentation available at: /api/docs/")
        
        # 5. Additional configurations
        self._configure_security(app)
        self._configure_logging(app)
        
        print("🚀 All configurations initialized successfully!")
        
        return app
    
    def _configure_flask(self, app: Flask):
        """
        Konfigurasi dasar Flask
        
        Args:
            app: Flask application instance
        """
        # Environment-based configuration
        env = os.getenv('FLASK_ENV', 'development')
        
        if env == 'production':
            app.config.update({
                'DEBUG': False,
                'TESTING': False,
                'SECRET_KEY': os.getenv('SECRET_KEY', os.urandom(32).hex()),
                'ENABLE_CORS': True,
                'ENABLE_SWAGGER': False,  # Disable swagger in production
                'JSON_SORT_KEYS': False,
                'JSONIFY_PRETTYPRINT_REGULAR': False
            })
        else:  # development
            app.config.update({
                'DEBUG': True,
                'TESTING': False,
                'SECRET_KEY': 'dev-secret-key-change-in-production',
                'ENABLE_CORS': True,
                'ENABLE_SWAGGER': True,
                'JSON_SORT_KEYS': False,
                'JSONIFY_PRETTYPRINT_REGULAR': True
            })
        
        # Additional Flask configurations
        app.config.update({
            'JSON_AS_ASCII': False,  # Support UTF-8 characters
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max file upload
            'PERMANENT_SESSION_LIFETIME': 28800,  # 8 hours
        })
    
    def _configure_security(self, app: Flask):
        """
        Konfigurasi keamanan aplikasi
        
        Args:
            app: Flask application instance
        """
        # JWT Configuration
        self.auth_config.configure_jwt_secret(app)
        
        # Security Headers (sudah ada di CORS, tapi tambahan)
        @app.after_request
        def security_headers(response):
            # Additional security headers
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            
            return response
    
    def _configure_logging(self, app: Flask):
        """
        Konfigurasi logging
        
        Args:
            app: Flask application instance
        """
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not app.debug:
            # Setup file logging untuk production
            if not os.path.exists('logs'):
                os.mkdir('logs')
            
            file_handler = RotatingFileHandler(
                'logs/genset.log', 
                maxBytes=10240000,  # 10MB
                backupCount=10
            )
            
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('Genset application startup')
    
    def get_config_info(self) -> dict:
        """
        Mendapatkan informasi konfigurasi yang sedang aktif
        
        Returns:
            dict: Informasi konfigurasi
        """
        return {
            'cors_enabled': True,
            'swagger_enabled': True,
            'authentication': 'Bearer Token',
            'excluded_endpoints': self.auth_config.EXCLUDED_ENDPOINTS,
            'protected_endpoints': self.auth_config.PROTECTED_ENDPOINTS
        }


# Global instance
app_config = AppConfig()