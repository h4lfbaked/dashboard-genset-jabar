import hashlib
from datetime import datetime, timedelta
import secrets
from ApiResponse import ApiResponse

class LoginService:
    """
    Service untuk menangani autentikasi dan login pengguna
    Menggunakan data dummy sementara sebelum implementasi database
    """
    
    def __init__(self):
        # Data dummy pengguna - nanti akan diganti dengan database
        self.dummy_users = {
            'admin': {
                'username': 'admin',
                'password_hash': self._hash_password('admin123'),
                'role': 'administrator',
                'full_name': 'Administrator',
                'email': 'admin@genset.com',
                'is_active': True,
                'created_at': '2024-01-01 00:00:00'
            },
            'operator': {
                'username': 'operator',
                'password_hash': self._hash_password('operator123'),
                'role': 'operator',
                'full_name': 'Operator Genset',
                'email': 'operator@genset.com',
                'is_active': True,
                'created_at': '2024-01-01 00:00:00'
            },
            'technician': {
                'username': 'technician',
                'password_hash': self._hash_password('tech123'),
                'role': 'technician',
                'full_name': 'Teknisi Genset',
                'email': 'tech@genset.com',
                'is_active': True,
                'created_at': '2024-01-01 00:00:00'
            },
            'viewer': {
                'username': 'viewer',
                'password_hash': self._hash_password('viewer123'),
                'role': 'viewer',
                'full_name': 'Viewer Only',
                'email': 'viewer@genset.com',
                'is_active': True,
                'created_at': '2024-01-01 00:00:00'
            }
        }
        
        # Storage untuk session tokens (dalam produksi gunakan Redis/Database)
        self.active_sessions = {}
    
    def _hash_password(self, password):
        """
        Hash password menggunakan SHA-256
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def authenticate_user(self, username, password):
        """
        Melakukan autentikasi pengguna
        
        Args:
            username (str): Username pengguna
            password (str): Password pengguna
            
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            # Validasi input
            if not username or not password:
                return ApiResponse.error("Username dan password harus diisi", 400, "INVALID_INPUT")
            
            # Cek apakah username ada
            if username not in self.dummy_users:
                return ApiResponse.error("Username atau password salah", 401, "INVALID_CREDENTIALS")
            
            user = self.dummy_users[username]
            
            # Cek apakah user aktif
            if not user.get('is_active', False):
                return ApiResponse.error("Akun tidak aktif", 403, "ACCOUNT_INACTIVE")
            
            # Verifikasi password
            password_hash = self._hash_password(password)
            if password_hash != user['password_hash']:
                return ApiResponse.error("Username atau password salah", 401, "INVALID_CREDENTIALS")
            
            # Return user data tanpa password hash
            user_data = {
                'username': user['username'],
                'role': user['role'],
                'full_name': user['full_name'],
                'email': user['email'],
                'is_active': user['is_active'],
                'created_at': user['created_at'],
                'last_login': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            return ApiResponse.success(user_data, "Autentikasi berhasil")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam autentikasi: {str(e)}", 500, "AUTHENTICATION_ERROR")
    
    def create_session(self, user_data):
        """
        Membuat session token untuk pengguna yang berhasil login
        
        Args:
            user_data (dict): Data pengguna
            
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            # Validasi input
            if not user_data or not isinstance(user_data, dict):
                return ApiResponse.error("Data pengguna tidak valid", 400, "INVALID_USER_DATA")
            
            # Generate session token
            session_token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=8)  # Session 8 jam
            
            # Simpan session data
            self.active_sessions[session_token] = {
                'username': user_data['username'],
                'role': user_data['role'],
                'full_name': user_data['full_name'],
                'created_at': datetime.now(),
                'expires_at': expires_at,
                'last_activity': datetime.now()
            }
            
            session_data = {
                'session_token': session_token,
                'expires_at': expires_at.isoformat(),
                'user': user_data
            }
            
            return ApiResponse.success(session_data, "Session berhasil dibuat")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam membuat session: {str(e)}", 500, "SESSION_CREATION_ERROR")
    
    def validate_session(self, session_token):
        """
        Validasi session token
        
        Args:
            session_token (str): Session token
            
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            if not session_token:
                return ApiResponse.error("Session token tidak ditemukan", 401, "NO_SESSION_TOKEN")
            
            if session_token not in self.active_sessions:
                return ApiResponse.error("Session tidak valid", 401, "INVALID_SESSION")
            
            session_data = self.active_sessions[session_token]
            
            # Cek apakah session sudah expire
            if datetime.now() > session_data['expires_at']:
                # Hapus session yang sudah expire
                del self.active_sessions[session_token]
                return ApiResponse.error("Session sudah expired", 401, "SESSION_EXPIRED")
            
            # Update last activity
            session_data['last_activity'] = datetime.now()
            
            return ApiResponse.success(session_data, "Session valid")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam validasi session: {str(e)}", 500, "SESSION_VALIDATION_ERROR")
    
    def logout(self, session_token):
        """
        Logout pengguna dan hapus session
        
        Args:
            session_token (str): Session token
            
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            if not session_token:
                return ApiResponse.error("Session token tidak ditemukan", 400, "NO_SESSION_TOKEN")
            
            if session_token in self.active_sessions:
                del self.active_sessions[session_token]
                return ApiResponse.success(None, "Logout berhasil")
            else:
                return ApiResponse.error("Session tidak ditemukan", 404, "SESSION_NOT_FOUND")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam logout: {str(e)}", 500, "LOGOUT_ERROR")
    
    def get_user_by_username(self, username):
        """
        Mendapatkan data pengguna berdasarkan username
        
        Args:
            username (str): Username pengguna
            
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            if not username:
                return ApiResponse.error("Username tidak boleh kosong", 400, "INVALID_INPUT")
            
            if username not in self.dummy_users:
                return ApiResponse.error("Pengguna tidak ditemukan", 404, "USER_NOT_FOUND")
            
            user = self.dummy_users[username]
            
            # Return user data tanpa password hash
            user_data = {
                'username': user['username'],
                'role': user['role'],
                'full_name': user['full_name'],
                'email': user['email'],
                'is_active': user['is_active'],
                'created_at': user['created_at']
            }
            
            return ApiResponse.success(user_data, "Data pengguna berhasil ditemukan")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam mendapatkan user: {str(e)}", 500, "GET_USER_ERROR")
    
    def check_user_permission(self, role, required_permission):
        """
        Cek permission berdasarkan role
        
        Args:
            role (str): Role pengguna
            required_permission (str): Permission yang dibutuhkan
            
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            if not role or not required_permission:
                return ApiResponse.error("Role dan permission harus diisi", 400, "INVALID_INPUT")
            
            # Definisi permission untuk setiap role
            role_permissions = {
                'administrator': ['read', 'write', 'delete', 'manage_users', 'system_config'],
                'operator': ['read', 'write', 'start_stop_genset'],
                'technician': ['read', 'write', 'maintenance', 'diagnostics'],
                'viewer': ['read']
            }
            
            user_permissions = role_permissions.get(role, [])
            has_permission = required_permission in user_permissions
            
            permission_data = {
                'role': role,
                'required_permission': required_permission,
                'has_permission': has_permission,
                'available_permissions': user_permissions
            }
            
            if has_permission:
                return ApiResponse.success(permission_data, f"Permission '{required_permission}' ditemukan untuk role '{role}'")
            else:
                return ApiResponse.error(f"Permission '{required_permission}' tidak tersedia untuk role '{role}'", 403, "INSUFFICIENT_PERMISSION", permission_data)
                
        except Exception as e:
            return ApiResponse.error(f"Error dalam cek permission: {str(e)}", 500, "PERMISSION_CHECK_ERROR")
    
    def get_all_users(self):
        """
        Mendapatkan semua pengguna (untuk admin)
        
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            users_list = []
            for username, user in self.dummy_users.items():
                user_data = {
                    'username': user['username'],
                    'role': user['role'],
                    'full_name': user['full_name'],
                    'email': user['email'],
                    'is_active': user['is_active'],
                    'created_at': user['created_at']
                }
                users_list.append(user_data)
            
            users_summary = {
                'users': users_list,
                'total_count': len(users_list),
                'active_count': sum(1 for user in users_list if user['is_active']),
                'roles_distribution': {}
            }
            
            # Hitung distribusi role
            for user in users_list:
                role = user['role']
                users_summary['roles_distribution'][role] = users_summary['roles_distribution'].get(role, 0) + 1
            
            return ApiResponse.success(users_summary, f"Berhasil mengambil {len(users_list)} pengguna")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam mendapatkan semua users: {str(e)}", 500, "GET_ALL_USERS_ERROR")
    
    def get_active_sessions_count(self):
        """
        Mendapatkan jumlah session yang aktif
        
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            active_count = len(self.active_sessions)
            
            # Detail session info
            session_info = {
                'active_sessions_count': active_count,
                'sessions_details': []
            }
            
            for token, session_data in self.active_sessions.items():
                session_detail = {
                    'username': session_data['username'],
                    'role': session_data['role'],
                    'created_at': session_data['created_at'].isoformat(),
                    'expires_at': session_data['expires_at'].isoformat(),
                    'last_activity': session_data['last_activity'].isoformat()
                }
                session_info['sessions_details'].append(session_detail)
            
            return ApiResponse.success(session_info, f"Terdapat {active_count} session aktif")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam mendapatkan session count: {str(e)}", 500, "SESSION_COUNT_ERROR")
    
    def cleanup_expired_sessions(self):
        """
        Membersihkan session yang sudah expire
        
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            current_time = datetime.now()
            expired_sessions = []
            
            for token, session_data in self.active_sessions.items():
                if current_time > session_data['expires_at']:
                    expired_sessions.append(token)
            
            for token in expired_sessions:
                del self.active_sessions[token]
            
            cleanup_result = {
                'expired_sessions_removed': len(expired_sessions),
                'remaining_sessions': len(self.active_sessions),
                'cleanup_time': current_time.isoformat()
            }
            
            return ApiResponse.success(cleanup_result, f"Berhasil menghapus {len(expired_sessions)} session yang expired")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam cleanup sessions: {str(e)}", 500, "SESSION_CLEANUP_ERROR")
    
    def login(self, username, password):
        """
        Method lengkap untuk login (authenticate + create session)
        
        Args:
            username (str): Username pengguna
            password (str): Password pengguna
            
        Returns:
            tuple: ApiResponse dengan session data atau error
        """
        try:
            # Authenticate user
            auth_response = self.authenticate_user(username, password)
            
            # Cek apakah autentikasi gagal
            if not auth_response[0].json['success']:
                return auth_response
            
            # Ambil user data dari response autentikasi
            user_data = auth_response[0].json['data']
            
            # Buat session
            session_response = self.create_session(user_data)
            
            # Cek apakah pembuatan session gagal
            if not session_response[0].json['success']:
                return session_response
            
            # Ambil session data
            session_data = session_response[0].json['data']
            
            # Return response menggunakan login_success dari ApiResponse
            return ApiResponse.login_success(
                user_data=session_data['user'],
                session_token=session_data['session_token'],
                expires_at=session_data['expires_at']
            )
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam login: {str(e)}", 500, "LOGIN_ERROR")
    
    def get_session_info(self, session_token):
        """
        Mendapatkan informasi lengkap session
        
        Args:
            session_token (str): Session token
            
        Returns:
            tuple: ApiResponse dengan info session atau error
        """
        try:
            validation_response = self.validate_session(session_token)
            
            # Cek apakah validasi gagal
            if not validation_response[0].json['success']:
                return validation_response
            
            session_data = validation_response[0].json['data']
            
            # Tambahkan info tambahan
            session_info = {
                'session_data': session_data,
                'time_remaining': (session_data['expires_at'] - datetime.now()).total_seconds(),
                'is_valid': True
            }
            
            return ApiResponse.success(session_info, "Informasi session berhasil diambil")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam mendapatkan session info: {str(e)}", 500, "SESSION_INFO_ERROR")
    
    def extend_session(self, session_token, additional_hours=2):
        """
        Perpanjang waktu expire session
        
        Args:
            session_token (str): Session token
            additional_hours (int): Jam tambahan untuk extend
            
        Returns:
            tuple: ApiResponse success atau error
        """
        try:
            if not session_token:
                return ApiResponse.error("Session token tidak ditemukan", 400, "NO_SESSION_TOKEN")
            
            if session_token not in self.active_sessions:
                return ApiResponse.error("Session tidak valid", 401, "INVALID_SESSION")
            
            # Extend session
            current_expires = self.active_sessions[session_token]['expires_at']
            new_expires = current_expires + timedelta(hours=additional_hours)
            self.active_sessions[session_token]['expires_at'] = new_expires
            
            extend_result = {
                'session_token': session_token,
                'previous_expires_at': current_expires.isoformat(),
                'new_expires_at': new_expires.isoformat(),
                'extended_by_hours': additional_hours
            }
            
            return ApiResponse.success(extend_result, f"Session diperpanjang {additional_hours} jam")
            
        except Exception as e:
            return ApiResponse.error(f"Error dalam extend session: {str(e)}", 500, "EXTEND_SESSION_ERROR")