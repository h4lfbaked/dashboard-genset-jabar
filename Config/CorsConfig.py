from flask import Flask
from flask_cors import CORS

class CorsConfig:
    """
    Konfigurasi CORS (Cross-Origin Resource Sharing) untuk Flask app
    """
    
    @staticmethod
    def init_cors(app: Flask):
        """
        Inisialisasi CORS untuk Flask app
        
        Args:
            app: Flask application instance
        """
        # CORS configuration
        cors_config = {
            'origins': [
                'http://localhost:3000',      # React development server
                'http://localhost:5000',      # Flask development server
                'http://127.0.0.1:3000',     # Alternative localhost
                'http://127.0.0.1:5000',     # Alternative localhost
                'https://your-production-domain.com'  # Production domain
            ],
            'methods': [
                'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'
            ],
            'allow_headers': [
                'Content-Type',
                'Authorization',
                'X-Requested-With',
                'X-CSRF-Token',
                'Accept',
                'Origin',
                'User-Agent',
                'Cache-Control'
            ],
            'expose_headers': [
                'Content-Range',
                'X-Content-Range',
                'Authorization'
            ],
            'supports_credentials': True,  # Allow cookies and credentials
            'max_age': 3600  # Preflight cache duration (1 hour)
        }
        
        # Initialize CORS
        cors = CORS(app, **cors_config)
        
        # Custom CORS headers for specific routes
        @app.after_request
        def after_request(response):
            """
            Add additional CORS headers to all responses
            """
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
            response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS')
            response.headers.add('Access-Control-Expose-Headers', 'Authorization')
            
            # Security headers
            response.headers.add('X-Content-Type-Options', 'nosniff')
            response.headers.add('X-Frame-Options', 'DENY')
            response.headers.add('X-XSS-Protection', '1; mode=block')
            
            return response
        
        return cors
    
    @staticmethod
    def get_allowed_origins():
        """
        Mendapatkan daftar origins yang diizinkan
        
        Returns:
            list: Daftar origins yang diizinkan
        """
        return [
            'http://localhost:3000',
            'http://localhost:5000',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5000',
            'https://your-production-domain.com'
        ]
    
    @staticmethod
    def is_origin_allowed(origin: str) -> bool:
        """
        Cek apakah origin diizinkan
        
        Args:
            origin: Origin yang akan dicek
            
        Returns:
            bool: True jika diizinkan
        """
        allowed_origins = CorsConfig.get_allowed_origins()
        return origin in allowed_origins or origin.endswith('.localhost')
    
    @staticmethod
    def configure_development_cors(app: Flask):
        """
        Konfigurasi CORS untuk development (lebih permissive)
        
        Args:
            app: Flask application instance
        """
        cors_config = {
            'origins': '*',  # Allow all origins in development
            'methods': '*',  # Allow all methods
            'allow_headers': '*',  # Allow all headers
            'supports_credentials': True
        }
        
        return CORS(app, **cors_config)
    
    @staticmethod
    def configure_production_cors(app: Flask, allowed_domains: list = None):
        """
        Konfigurasi CORS untuk production (lebih ketat)
        
        Args:
            app: Flask application instance
            allowed_domains: List domain yang diizinkan
        """
        if allowed_domains is None:
            allowed_domains = ['https://your-production-domain.com']
        
        cors_config = {
            'origins': allowed_domains,
            'methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
            'allow_headers': [
                'Content-Type',
                'Authorization',
                'X-Requested-With'
            ],
            'supports_credentials': True,
            'max_age': 86400  # 24 hours cache
        }
        
        return CORS(app, **cors_config)