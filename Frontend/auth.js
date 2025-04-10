document.addEventListener('DOMContentLoaded', function() {
    // Check if the token exists in sessionStorage
    const token = sessionStorage.getItem('token');

    // If the token doesn't exist, redirect to the login page
    if (!token) {
        window.location.href = '/Frontend/Admin/login.html'; // Redirect to the login page
    }
});
