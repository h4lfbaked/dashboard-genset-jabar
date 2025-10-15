from flask import Flask
from flasgger import Swagger
from flasgger.utils import swag_from
import os

class SwaggerConfig:
    """
    Konfigurasi Swagger UI untuk dokumentasi API
    """
    
    @staticmethod
    def init_swagger(app: Flask):
        """
        Inisialisasi Swagger untuk Flask app
        
        Args:
            app: Flask application instance
        """
        # Swagger configuration
        swagger_config = {
            "headers": [],
            "specs": [
                {
                    "endpoint": 'apispec',
                    "route": '/api/docs/apispec.json',
                    "rule_filter": lambda rule: True,
                    "model_filter": lambda tag: True,
                }
            ],
            "static_url_path": "/flasgger_static",
            "swagger_ui": True,
            "specs_route": "/api/docs/"
        }
        
        # Swagger template
        swagger_template = {
            "swagger": "2.0",
            "info": {
                "title": "Genset Management API",
                "description": "API untuk sistem manajemen genset dengan autentikasi Bearer Token",
                "contact": {
                    "name": "Genset API Support",
                    "email": "support@genset.com"
                },
                "version": "1.0.0"
            },
            "basePath": "/api",
            "schemes": [
                "http",
                "https"
            ],
            "securityDefinitions": {
                "Bearer": {
                    "type": "apiKey",
                    "name": "Authorization",
                    "in": "header",
                    "description": "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'"
                }
            },
            "security": [
                {
                    "Bearer": []
                }
            ],
            "tags": [
                {
                    "name": "Authentication",
                    "description": "Endpoint untuk autentikasi dan manajemen session"
                },
                {
                    "name": "User Management",
                    "description": "Endpoint untuk manajemen pengguna"
                },
                {
                    "name": "System",
                    "description": "Endpoint sistem dan monitoring"
                },
                {
                    "name": "Genset Operations",
                    "description": "Endpoint untuk operasi genset (coming soon)"
                }
            ],
            "definitions": {
                "LoginRequest": {
                    "type": "object",
                    "required": ["username", "password"],
                    "properties": {
                        "username": {
                            "type": "string",
                            "description": "Username pengguna",
                            "example": "admin"
                        },
                        "password": {
                            "type": "string",
                            "description": "Password pengguna",
                            "example": "admin123"
                        }
                    }
                },
                "SuccessResponse": {
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "boolean",
                            "example": True
                        },
                        "status_code": {
                            "type": "integer",
                            "example": 200
                        },
                        "message": {
                            "type": "string",
                            "example": "Operation successful"
                        },
                        "data": {
                            "type": "object"
                        },
                        "timestamp": {
                            "type": "string",
                            "format": "date-time"
                        }
                    }
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "boolean",
                            "example": False
                        },
                        "status_code": {
                            "type": "integer",
                            "example": 400
                        },
                        "message": {
                            "type": "string",
                            "example": "Error message"
                        },
                        "error_code": {
                            "type": "string",
                            "example": "ERROR_CODE"
                        },
                        "details": {
                            "type": "object"
                        },
                        "timestamp": {
                            "type": "string",
                            "format": "date-time"
                        }
                    }
                },
                "UserData": {
                    "type": "object",
                    "properties": {
                        "username": {
                            "type": "string",
                            "example": "admin"
                        },
                        "role": {
                            "type": "string",
                            "example": "administrator"
                        },
                        "full_name": {
                            "type": "string",
                            "example": "Administrator"
                        },
                        "email": {
                            "type": "string",
                            "example": "admin@genset.com"
                        },
                        "is_active": {
                            "type": "boolean",
                            "example": True
                        },
                        "created_at": {
                            "type": "string",
                            "example": "2024-01-01 00:00:00"
                        }
                    }
                },
                "LoginResponse": {
                    "type": "object",
                    "properties": {
                        "success": {
                            "type": "boolean",
                            "example": True
                        },
                        "status_code": {
                            "type": "integer",
                            "example": 200
                        },
                        "message": {
                            "type": "string",
                            "example": "Login successful"
                        },
                        "data": {
                            "type": "object",
                            "properties": {
                                "user": {
                                    "$ref": "#/definitions/UserData"
                                },
                                "session_token": {
                                    "type": "string",
                                    "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                },
                                "expires_at": {
                                    "type": "string",
                                    "format": "date-time"
                                }
                            }
                        },
                        "timestamp": {
                            "type": "string",
                            "format": "date-time"
                        }
                    }
                }
            }
        }
        
        # Initialize Swagger
        swagger = Swagger(app, config=swagger_config, template=swagger_template)
        
        return swagger

    @staticmethod
    def get_swagger_specs_dir():
        """
        Mendapatkan directory untuk menyimpan swagger specs
        
        Returns:
            str: Path ke directory swagger specs
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        specs_dir = os.path.join(current_dir, 'swagger_specs')
        
        # Buat directory jika belum ada
        if not os.path.exists(specs_dir):
            os.makedirs(specs_dir)
        
        return specs_dir