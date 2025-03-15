# GoingOut Backend API
    ## APIs for user account management, including registration, login, password reset, etc.
    ### How to Deploy
    - Install dependencies: `npm install`
    - Deploy to Lambda (use Serverless framework): `serverless deploy`
    ### Test with cURL:
    - /auth/register: `curl -X POST -d '{"email": "test@example.com", "password": "securepassword"}' http://yourapi.com/auth/register`
    - /auth/forgot-password: `curl -X POST -d '{"email": "test@example.com"}' http://yourapi.com/auth/forgot-password`
    - /auth/reset-password: `curl -X POST -d '{"token": "reset_token_here", "newPassword": "newpassword"}' http://yourapi.com/auth/reset-password`