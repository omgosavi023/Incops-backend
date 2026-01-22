document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Get form values
    const email = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // Basic validation
    if (!email || !password) {
        alert('Please fill in all fields');
        return;
    }
    
    // Add @domain if missing (for testing)
    const emailToSend = email.includes('@') ? email : `${email}@incops.dev`;
    
    try {
        // Show loading state
        const submitBtn = document.querySelector('.login-btn');
        const originalText = submitBtn.textContent;
        submitBtn.textContent = 'Logging in...';
        submitBtn.disabled = true;
        
        console.log('Sending login request to backend...');
        
        // Call backend API
        const response = await fetch('http://localhost:3001/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                email: emailToSend, 
                password: password 
            })
        });
        
        console.log('Response status:', response.status);
        
        const data = await response.json();
        console.log('Response data:', data);
        
        if (response.ok) {
            // ========== IMPORTANT: STORE TOKEN HERE ==========
            // Store token in localStorage for future API calls
            localStorage.setItem('incops_token', data.token);
            
            // Store user info (for displaying username, role, etc.)
            localStorage.setItem('incops_user', JSON.stringify(data.user));
            
            // Store token expiry time (optional but good practice)
            const expiryTime = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
            localStorage.setItem('incops_token_expiry', expiryTime.toString());
            // ================================================
            
            alert(`✅ Login Successful! Welcome ${data.user.username}`);
            console.log('Token received:', data.token.substring(0, 50) + '...');
            
            // Optional: Test the token immediately
            console.log('Testing token with protected API...');
            try {
                const testResponse = await fetch('http://localhost:3001/api/profile', {
                    headers: {
                        'Authorization': `Bearer ${data.token}`
                    }
                });
                if (testResponse.ok) {
                    console.log('✅ Token works! Redirecting to dashboard...');
                }
            } catch (testError) {
                console.log('⚠️ Token test failed, but continuing...');
            }
            
            // Redirect to dashboard
            window.location.href = "dashboard.html";
        } else {
            alert(`❌ Login Failed: ${data.error || 'Unknown error'}`);
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert('⚠️ Cannot connect to server. Please check:\n1. Backend is running (npm run dev)\n2. Port 3001 is accessible\n3. No firewall blocking');
    } finally {
        // Reset button state
        const submitBtn = document.querySelector('.login-btn');
        submitBtn.textContent = 'Log In';
        submitBtn.disabled = false;
    }
});

// Optional: Add test credentials button for easy testing
window.addEventListener('DOMContentLoaded', () => {
    // Create a test button if not exists
    if (!document.getElementById('testCredentials')) {
        const testBtn = document.createElement('button');
        testBtn.id = 'testCredentials';
        testBtn.textContent = 'Fill Test Credentials';
        testBtn.style.cssText = `
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 15px;
            font-size: 14px;
        `;
        testBtn.onclick = () => {
            document.getElementById('username').value = 'admin';
            document.getElementById('password').value = 'password123';
        };
        document.querySelector('.login-form').appendChild(testBtn);
    }
    
    // Check if user is already logged in (optional)
    const token = localStorage.getItem('incops_token');
    const user = localStorage.getItem('incops_user');
    
    if (token && user) {
        console.log('User already logged in. Token exists.');
        
        // Optional: Auto-redirect if already logged in
        // window.location.href = "dashboard.html";
    }
});

// Helper function to get token for API calls
function getAuthToken() {
    const token = localStorage.getItem('incops_token');
    
    // Check if token expired (if we stored expiry time)
    const expiry = localStorage.getItem('incops_token_expiry');
    if (expiry && Date.now() > parseInt(expiry)) {
        console.log('Token expired');
        localStorage.removeItem('incops_token');
        localStorage.removeItem('incops_user');
        localStorage.removeItem('incops_token_expiry');
        return null;
    }
    
    return token;
}

// Helper function to logout
function logout() {
    localStorage.removeItem('incops_token');
    localStorage.removeItem('incops_user');
    localStorage.removeItem('incops_token_expiry');
    window.location.href = "index.html";
}