
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const db = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT,
});

exports.handler = async (event) => {
    console.log("Received event:", event);
    const route = event.path;
    const method = event.httpMethod;

    if (route === "/auth/register" && method === "POST") return await registerUser(event);
    if (route === "/auth/login" && method === "POST") return await loginUser(event);
    if (route === "/user/profile" && method === "PATCH") return await updateUserProfile(event);
    if (route === "/user/profile" && method === "DELETE") return await deleteUserProfile(event);
    if (route === "/auth/forgot-password" && method === "POST") return await forgotPassword(event);
    if (route === "/auth/reset-password" && method === "POST") return await resetPassword(event);
    if (route === "/auth/verify-email" && method === "POST") return await verifyEmail(event);
    if (route === "/auth/resend-verification" && method === "POST") return await resendVerificationEmail(event);
    if (route === "/user/interests" && method === "GET") return await getUserInterests(event);
    if (route === "/user/interests" && method === "PATCH") return await updateUserInterests(event);

    return { statusCode: 404, body: JSON.stringify({ error: "Route not found" }) };
};

// ✅ Register API
const registerUser = async (event) => {
    const { email, password, full_name, date_of_birth, postal_code } = JSON.parse(event.body || "{}");
    const existingUser = await db.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
        return { statusCode: 400, body: JSON.stringify({ error: "Email already registered!" }) };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
        "INSERT INTO users (full_name, email, password_hash, date_of_birth, postal_code) VALUES ($1, $2, $3, $4, $5) RETURNING id",
        [full_name, email, hashedPassword, date_of_birth, postal_code]
    );

    await sendVerificationEmail(email);

    return { statusCode: 201, body: JSON.stringify({ message: "User registered successfully!", user: { id: result.rows[0].id, email } }) };
};

// ✅ Login API
const loginUser = async (event) => {
    const { email, password } = JSON.parse(event.body || "{}");
    const result = await db.query("SELECT id, password_hash FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return { statusCode: 401, body: JSON.stringify({ error: "Invalid email or password" }) };

    const validPassword = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!validPassword) return { statusCode: 401, body: JSON.stringify({ error: "Invalid email or password" }) };

    const token = jwt.sign({ id: result.rows[0].id, email }, process.env.JWT_SECRET, { expiresIn: "7d" });
    return { statusCode: 200, body: JSON.stringify({ token, user: { id: result.rows[0].id, email } }) };
};

// ✅ Update Profile API
const updateUserProfile = async (event) => {
    const token = event.headers.Authorization || event.headers.authorization;
    if (!token) return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized" }) };

    let user;
    try {
        user = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    } catch (err) {
        return { statusCode: 401, body: JSON.stringify({ error: "Invalid token" }) };
    }

    const { email, full_name, postal_code } = JSON.parse(event.body || "{}");
    let updates = [], params = [], idx = 1;

    if (full_name) { updates.push(`full_name = $${idx++}`); params.push(full_name); }
    if (postal_code) { updates.push(`postal_code = $${idx++}`); params.push(postal_code); }
    if (email) { updates.push(`pending_email = $${idx++}`); params.push(email); }

    if (!updates.length) return { statusCode: 400, body: JSON.stringify({ error: "No valid fields to update" }) };

    params.push(user.id);
    await db.query(`UPDATE users SET ${updates.join(", ")} WHERE id = $${idx}`, params);
    return { statusCode: 200, body: JSON.stringify({ message: "Profile updated. Please verify your new email to complete changes." }) };
};

// ✅ Delete (Soft Delete) API
const deleteUserProfile = async (event) => {
    const token = event.headers.Authorization || event.headers.authorization;
    if (!token) return { statusCode: 401, body: JSON.stringify({ error: "Unauthorized" }) };

    let user;
    try {
        user = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    } catch (err) {
        return { statusCode: 401, body: JSON.stringify({ error: "Invalid token" }) };
    }

    const { password } = JSON.parse(event.body || "{}");
    const result = await db.query("SELECT password_hash FROM users WHERE id = $1", [user.id]);
    if (result.rows.length === 0) return { statusCode: 404, body: JSON.stringify({ error: "User not found" }) };

    const validPassword = await bcrypt.compare(password, result.rows[0].password_hash);
    if (!validPassword) return { statusCode: 403, body: JSON.stringify({ error: "Incorrect password" }) };

    await db.query("UPDATE users SET active = false, deletion_requested_at = NOW() WHERE id = $1", [user.id]);
    return { statusCode: 200, body: JSON.stringify({ message: "Your account has been deactivated. You can reactivate within 30 days." }) };
};

// ✅ Forgot Password API
const forgotPassword = async (event) => {
    const { email } = JSON.parse(event.body || "{}");
    const result = await db.query("SELECT id FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) return { statusCode: 404, body: JSON.stringify({ error: "User not found" }) };

    const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '15m' });

    await db.query("UPDATE users SET reset_token = $1, reset_token_expires = NOW() + INTERVAL '15 minutes' WHERE email = $2", [resetToken, email]);

    await sendResetPasswordEmail(email, resetToken);

    return { statusCode: 200, body: JSON.stringify({ message: "Password reset email sent." }) };
};

// ✅ Reset Password API
const resetPassword = async (event) => {
    const { token, newPassword } = JSON.parse(event.body || "{}");

    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        return { statusCode: 401, body: JSON.stringify({ error: "Invalid or expired token" }) };
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.query("UPDATE users SET password_hash = $1, reset_token = NULL WHERE email = $2", [hashedPassword, decoded.email]);

    return { statusCode: 200, body: JSON.stringify({ message: "Password reset successfully." }) };
};

// ✅ Verify Email API
const verifyEmail = async (event) => {
    const { token } = JSON.parse(event.body || "{}");

    let decoded;
    try {
        decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        return { statusCode: 401, body: JSON.stringify({ error: "Invalid or expired token" }) };
    }

    await db.query("UPDATE users SET email_verified = true WHERE email = $1", [decoded.email]);
    return { statusCode: 200, body: JSON.stringify({ message: "Email verified successfully." }) };
};

// ✅ Resend Verification Email
const resendVerificationEmail = async (event) => {
    const { email } = JSON.parse(event.body || "{}");
    await sendVerificationEmail(email);
    return { statusCode: 200, body: JSON.stringify({ message: "Verification email resent." }) };
};

// ✅ Helper function for sending email via AWS SES
const sendVerificationEmail = async (email) => {
    const transporter = nodemailer.createTransport({
        service: 'SES',
        auth: {
            user: process.env.SES_USER,
            pass: process.env.SES_PASS
        }
    });

    const mailOptions = {
        from: process.env.SES_USER,
        to: email,
        subject: 'Please Verify Your Email',
        text: 'Click this link to verify your email: https://yourplatform.com/verify-email?token=YOUR_TOKEN'
    };

    await transporter.sendMail(mailOptions);
};
