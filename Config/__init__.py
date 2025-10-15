"""
Configuration module untuk Genset Flask Application

Module ini berisi semua konfigurasi yang diperlukan untuk:
- CORS (Cross-Origin Resource Sharing)
- Swagger UI untuk dokumentasi API
- Bearer Token Authentication
- Security headers
- Logging configuration

Usage:
    from Config import app_config
    
    app = Flask(__name__)
    app_config.init_app(app)
"""

from .AppConfig import app_config, AppConfig
from .AuthConfig import auth_config, AuthConfig
from .CorsConfig import CorsConfig
from .SwaggerConfig import SwaggerConfig

__all__ = [
    'app_config',
    'auth_config',
    'AppConfig',
    'AuthConfig', 
    'CorsConfig',
    'SwaggerConfig'
]

# Version info
__version__ = '1.0.0'
__author__ = 'Genset Team'