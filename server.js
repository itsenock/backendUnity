require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Initialize Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// Helper function to validate email format
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Helper function to validate phone number format
function isValidPhoneNumber(phone) {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/; // E.164 format
    return phoneRegex.test(phone);
}

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate input format
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Query the database to find the user
    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

    if (error || !user) {
        return res.status(401).json({ error: 'Invalid Username or Password. Please try again.' });
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid Username or Password. Please try again.' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Return success response
    return res.status(200).json({
        message: 'Logged in successfully',
        user: { fullname: user.fullname, email: user.email, phone_number: user.phone_number },
        token,
    });
});

// Signup endpoint
app.post('/signup', async (req, res) => {
    const { fullname, email, phone_number, password, confirm_password } = req.body;

    // Validate input format
    if (!fullname || !email || !phone_number || !password || !confirm_password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    if (!isValidEmail(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    if (!isValidPhoneNumber(phone_number)) {
        return res.status(400).json({ error: 'Invalid phone number format' });
    }
    if (password !== confirm_password) {
        return res.status(400).json({ error: 'Passwords do not match' });
    }

    // Check if the email already exists in the database
    const { data: existingUser, error: fetchError } = await supabase
        .from('users')
        .select('*')
        .eq('email', email)
        .single();

    if (existingUser) {
        return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash the password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert the new user into the database
    const { data: newUser, error: insertError } = await supabase
        .from('users')
        .insert([{ fullname, email, phone_number, password_hash: passwordHash }])
        .select()
        .single();

    if (insertError) {
        return res.status(500).json({ error: 'Failed to create user' });
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: newUser.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Return success response
    return res.status(200).json({
        message: 'Registered successfully',
        user: { fullname: newUser.fullname, email: newUser.email, phone_number: newUser.phone_number },
        token,
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});