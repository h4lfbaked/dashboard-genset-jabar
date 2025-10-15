"""
Test script untuk Genset Flask API dengan Bearer Token Authentication

Usage:
    python test_api.py
"""

import requests
import json
from datetime import datetime

class GensetAPITester:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session_token = None
        self.headers = {'Content-Type': 'application/json'}
        
    def print_response(self, response, title="Response"):
        """Print formatted response"""
        print(f"\n{'='*50}")
        print(f"{title}")
        print(f"{'='*50}")
        print(f"Status Code: {response.status_code}")
        print(f"Headers: {dict(response.headers)}")
        print("Response Body:")
        try:
            print(json.dumps(response.json(), indent=2, ensure_ascii=False))
        except:
            print(response.text)
        print(f"{'='*50}")
    
    def test_api_status(self):
        """Test API status endpoint (public)"""
        print("\n🔍 Testing API Status (Public Endpoint)")
        response = requests.get(f"{self.base_url}/api/status")
        self.print_response(response, "API Status")
        return response.status_code == 200
    
    def test_login(self, username="admin", password="admin123"):
        """Test login endpoint"""
        print(f"\n🔐 Testing Login with {username}")
        
        login_data = {
            "username": username,
            "password": password
        }
        
        response = requests.post(
            f"{self.base_url}/api/auth/login",
            headers=self.headers,
            json=login_data
        )
        
        self.print_response(response, f"Login Response - {username}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                self.session_token = data['data']['session_token']
                print(f"✅ Login successful! Token saved.")
                return True
        
        print(f"❌ Login failed!")
        return False
    
    def test_protected_endpoint_without_token(self):
        """Test protected endpoint without Bearer token"""
        print("\n🚫 Testing Protected Endpoint WITHOUT Bearer Token")
        
        response = requests.get(f"{self.base_url}/api/auth/me")
        self.print_response(response, "Protected Endpoint Without Token")
        
        # Should return 401 Unauthorized
        return response.status_code == 401
    
    def test_protected_endpoint_with_token(self):
        """Test protected endpoint with Bearer token"""
        print("\n✅ Testing Protected Endpoint WITH Bearer Token")
        
        if not self.session_token:
            print("❌ No session token available. Please login first.")
            return False
        
        auth_headers = {
            **self.headers,
            'Authorization': f'Bearer {self.session_token}'
        }
        
        response = requests.get(
            f"{self.base_url}/api/auth/me",
            headers=auth_headers
        )
        
        self.print_response(response, "Protected Endpoint With Token")
        return response.status_code == 200
    
    def test_admin_only_endpoint(self):
        """Test admin-only endpoint"""
        print("\n👑 Testing Admin-Only Endpoint")
        
        if not self.session_token:
            print("❌ No session token available. Please login first.")
            return False
        
        auth_headers = {
            **self.headers,
            'Authorization': f'Bearer {self.session_token}'
        }
        
        response = requests.get(
            f"{self.base_url}/api/auth/users",
            headers=auth_headers
        )
        
        self.print_response(response, "Admin-Only Endpoint")
        return response.status_code == 200
    
    def test_data_endpoint(self):
        """Test data processing endpoint"""
        print("\n📊 Testing Data Processing Endpoint")
        
        if not self.session_token:
            print("❌ No session token available. Please login first.")
            return False
        
        auth_headers = {
            **self.headers,
            'Authorization': f'Bearer {self.session_token}'
        }
        
        test_data = {
            "message": "Hello from API test",
            "timestamp": datetime.now().isoformat(),
            "test_data": {
                "number": 42,
                "array": [1, 2, 3],
                "nested": {"key": "value"}
            }
        }
        
        response = requests.post(
            f"{self.base_url}/api/data",
            headers=auth_headers,
            json=test_data
        )
        
        self.print_response(response, "Data Processing Endpoint")
        return response.status_code == 200
    
    def test_system_health(self):
        """Test system health endpoint"""
        print("\n🏥 Testing System Health Endpoint")
        
        if not self.session_token:
            print("❌ No session token available. Please login first.")
            return False
        
        auth_headers = {
            **self.headers,
            'Authorization': f'Bearer {self.session_token}'
        }
        
        response = requests.get(
            f"{self.base_url}/api/system/health",
            headers=auth_headers
        )
        
        self.print_response(response, "System Health Endpoint")
        return response.status_code == 200
    
    def test_logout(self):
        """Test logout endpoint"""
        print("\n👋 Testing Logout")
        
        if not self.session_token:
            print("❌ No session token available. Please login first.")
            return False
        
        auth_headers = {
            **self.headers,
            'Authorization': f'Bearer {self.session_token}'
        }
        
        response = requests.post(
            f"{self.base_url}/api/auth/logout",
            headers=auth_headers
        )
        
        self.print_response(response, "Logout Response")
        
        if response.status_code == 200:
            self.session_token = None
            print("✅ Logout successful! Token cleared.")
            return True
        
        return False
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("🚀 Starting Genset API Test Suite")
        print(f"Base URL: {self.base_url}")
        print(f"Time: {datetime.now().isoformat()}")
        
        results = []
        
        # Test 1: API Status (public)
        results.append(("API Status", self.test_api_status()))
        
        # Test 2: Protected endpoint without token (should fail)
        results.append(("Protected Without Token", self.test_protected_endpoint_without_token()))
        
        # Test 3: Login
        results.append(("Login", self.test_login()))
        
        # Test 4: Protected endpoint with token (should succeed)
        results.append(("Protected With Token", self.test_protected_endpoint_with_token()))
        
        # Test 5: Admin-only endpoint
        results.append(("Admin Endpoint", self.test_admin_only_endpoint()))
        
        # Test 6: Data processing endpoint
        results.append(("Data Processing", self.test_data_endpoint()))
        
        # Test 7: System health endpoint
        results.append(("System Health", self.test_system_health()))
        
        # Test 8: Logout
        results.append(("Logout", self.test_logout()))
        
        # Test 9: Protected endpoint after logout (should fail)
        results.append(("Protected After Logout", not self.test_protected_endpoint_with_token()))
        
        # Print summary
        print(f"\n{'='*60}")
        print("TEST RESULTS SUMMARY")
        print(f"{'='*60}")
        
        passed = 0
        for test_name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{test_name:25} | {status}")
            if result:
                passed += 1
        
        print(f"{'='*60}")
        print(f"Total Tests: {len(results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {len(results) - passed}")
        print(f"Success Rate: {(passed/len(results)*100):.1f}%")
        print(f"{'='*60}")
        
        return passed == len(results)

def main():
    """Main test function"""
    tester = GensetAPITester()
    
    print("🔧 Genset Flask API Tester")
    print("Please make sure the Flask server is running on http://127.0.0.1:5000")
    print("Start server with: python Main.py")
    
    input("\nPress Enter to start testing...")
    
    success = tester.run_all_tests()
    
    if success:
        print("\n🎉 All tests passed! API is working correctly.")
    else:
        print("\n⚠️  Some tests failed. Please check the API implementation.")
    
    print("\n📖 API Documentation: http://127.0.0.1:5000/api/docs/")

if __name__ == "__main__":
    main()