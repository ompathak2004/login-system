const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');

exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            username,
            email,
            password: hashedPassword,
        });

        await user.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.login = async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ userId: user._id }, '8477b4889a841d9bc8f92da89c1fe64085c8161a07fc37e561fbe734cf8a01d12806c3d9a4de1c79e1ed90ef0d18fa2308f2fe4323c0e8f57e24febf4950e68b514f55cd624357d5d695cad26f8fee17', {
            expiresIn: '1h', 
        });

        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

const crypto = require('crypto');

function generateUniqueToken() {
    return new Promise((resolve, reject) => {
        crypto.randomBytes(20, (err, buffer) => {
            if (err) {
                reject(err);
            } else {
                const token = buffer.toString('hex');
                resolve(token);
            }
        });
    });
}

//forgot-password
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const resetToken = await generateUniqueToken();

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpires = Date.now() + 3600000; 
        await user.save();

        const resetLink = `http://your-website.com/reset-password?token=${resetToken}`;

        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: '<your-email-id>',
                pass: '<your-password>',
            },
        });

        const mailOptions = {
            from: 'your-email-id',
            to: email,
            subject: 'Password Reset',
            text: `You are receiving this email because you (or someone else) requested a password reset for your account.\n\n
          Please click on the following link to reset your password:\n\n
          ${resetLink}\n\n
          If you did not request this, please ignore this email and your password will remain unchanged.`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error);
                return res.status(500).json({ error: 'Email sending failed' });
            } else {
                console.log('Email sent: ' + info.response);
                res.status(200).json({ message: 'Password reset email sent' });
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

