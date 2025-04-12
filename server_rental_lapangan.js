// Server Code (server_rental_lapangan.js)

// Import Library
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();
const app = express();
const PORT = process.env.PORT || 6969;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'abcdefghijklmnopqrstuvwxyz01234567890[>_<]{._.}(0_0)',
    resave: false,
    saveUninitialized: true
}));

// Connect to MySQL DB
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'rental_lapangan'
});

db.connect(err => {
    if (err) {
        console.error('Failed to connect to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// SQL TABLES
const createUsersTable = `CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255),
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('manager', 'customer') NOT NULL
)`;

const createPasswordResetsTable = `CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL,
    expiry DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`;

const createBookingsTable = `CREATE TABLE IF NOT EXISTS bookings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    court_id INT NOT NULL,
    booking_date DATE NOT NULL,
    booking_time TIME NOT NULL,
    booking_duration INT NOT NULL,
    status ENUM('pending', 'paid', 'cancelled') DEFAULT 'pending',
    payment_amount INT NOT NULL,
    payment_method VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (court_id) REFERENCES courts(id)
);`;

const createTransactionsTable = `CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    booking_id INT NOT NULL,
    user_id INT NOT NULL,
    payment_amount INT NOT NULL,
    payment_method VARCHAR(255) NOT NULL,
    transaction_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);`;

const createCourtsTable = `CREATE TABLE IF NOT EXISTS courts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    court_type VARCHAR(255) NOT NULL,
    open_time TIME NOT NULL,
    close_time TIME NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);`;

db.query(createUsersTable, (err) => {
    if (err) throw err;
    console.log('Users table ready');
});

db.query(createPasswordResetsTable, (err) => {
    if (err) throw err;
    console.log('Password Resets table ready');
});

db.query(createBookingsTable, (err) => {
    if (err) throw err;
    console.log('Bookings table ready');
});

db.query(createTransactionsTable, (err) => {
    if (err) throw err;
    console.log('Transactions table ready');
});

db.query(createCourtsTable, (err) => {
    if (err) throw err;
    console.log('Courts table ready');
});

// REGISTER MANAGER
app.post('/register_manager', async (req, res) => {
    await handleRegister(req, res, 'manager');
});

// REGISTER CUSTOMER
app.post('/register_customer', async (req, res) => {
    await handleRegister(req, res, 'customer');
});

// REGISTER
function handleRegister(req, res, role) {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({
            message: "Username, password, and email are required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    db.query('SELECT id FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            return res.status(500).json({
                message: "Database error",
                status: 500,
                error: "Internal Server Error",
                response: null
            });
        }

        if (results.length > 0) {
            return res.status(409).json({
                message: "Username already taken",
                status: 409,
                error: "Conflict",
                response: null
            });
        }

        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({
                    message: "Hashing error",
                    status: 500,
                    error: "Internal Server Error",
                    response: null
                });
            }

            db.query('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                [username, hashedPassword, email, role],
                (err) => {
                    if (err) {
                        return res.status(500).json({
                            message: "Failed to register user",
                            status: 500,
                            error: "Internal Server Error",
                            response: null
                        });
                    }

                    res.status(201).json({
                        message: `User with role ${role} registered successfully`,
                        status: 201,
                        error: null,
                        response: { username, email, role }
                    });
                }
            );
        });
    });
}

// LOGIN MANAGER
app.post('/login_manager', (req, res) => {
    handleLogin(req, res, 'manager');
});

// LOGIN CUSTOMER
app.post('/login_customer', (req, res) => {
    handleLogin(req, res, 'customer');
});

// LOGIN
function handleLogin(req, res, role) {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            message: "Username/email and password are required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    const isEmail = username.includes('@');
    const identifierField = isEmail ? 'email' : 'username';

    const query = `SELECT * FROM users WHERE ${identifierField} = ? AND role = ?`;

    db.query(query, [username, role], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({
                message: "Invalid credentials or password",
                status: 401,
                error: "Unauthorized",
                response: null
            });
        }

        const validPassword = await bcrypt.compare(password, results[0].password);
        if (!validPassword) {
            return res.status(401).json({
                message: "Invalid credentials or password",
                status: 401,
                error: "Unauthorized",
                response: null
            });
        }

        req.session.userId = results[0].id;
        req.session.role = role;

        res.status(200).json({
            message: `Login as role ${role} successful`,
            status: 200,
            error: null,
            response: { role }
        });
    });
}

// LOGOUT
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({
                message: `Failed to logout`,
                status: 500,
                error: "Internal Server Error",
                response: null
            });
        }
        res.status(200).json({
            message: `Logged out successfully`,
            status: 200,
            error: null,
            response: null
        });
    });
});

// SEND RESET PASSWORD
app.post('/send_reset_password', (req, res) => {
    const { username, email } = req.body;

    if (!username && !email) {
        return res.status(400).json({
            message: "Username or email is required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    const query = username ? 'SELECT id, email FROM users WHERE username = ?' : 'SELECT id, email FROM users WHERE email = ?';
    const identifier = username || email;

    db.query(query, [identifier], (err, results) => {
        if (err || results.length === 0) return res.status(400).send('User not found');

        const userId = results[0].id;
        const userEmail = results[0].email;
        const token = crypto.randomBytes(32).toString('hex');
        const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 menit

        db.query(
            'INSERT INTO password_resets (user_id, token, expiry) VALUES (?, ?, ?)',
            [userId, token, expiry],
            (err) => {
                if (err) {
                    return res.status(500).json({
                        message: "Failed to create reset token",
                        status: 500,
                        error: "Internal Server Error",
                        response: null
                    });
                }

                const resetLink = `http://localhost:6969/reset_password/${token}`;
                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: process.env.EMAIL_USER,
                        pass: process.env.EMAIL_PASS,
                    },
                });

                const mailOptions = {
                    from: '<no-reply>',
                    to: userEmail,
                    subject: 'Reset Your Password',
                    html: `<p>Click the link below to reset your password:</p><a href="${resetLink}">Reset Password</a>`
                };

                transporter.sendMail(mailOptions, (err) => {
                    if (err) {
                        return res.status(500).json({
                            message: "Failed to send email",
                            status: 500,
                            error: "Internal Server Error",
                            response: null
                        });
                    } 
                    res.status(200).json({
                        message: "Password reset email sent",
                        status: 200,
                        error: null,
                        response: { userEmail }
                    });
                });
            }
        );
    });
});

// RESET PASSWORD
app.post('/reset_password/:token', async (req, res) => {
    const { token } = req.params;
    const { new_password } = req.body;
    if (!token || !new_password) {
        return res.status(400).json({
            message: "Token and new password required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    const now = new Date();
    db.query('SELECT * FROM password_resets WHERE token = ? AND expiry > ?', [token, now], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).json({
                message: "Invalid or expired token",
                status: 400,
                error: "Bad Request",
                response: null
            });
        }

        const userId = results[0].user_id;
        const hashedPassword = await bcrypt.hash(new_password, 10);

        db.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, userId], (err) => {
            if (err) {
                return res.status(500).json({
                    message: "Failed to reset password",
                    status: 500,
                    error: "Internal Server Error",
                    response: null
                });
            }

            db.query('DELETE FROM password_resets WHERE user_id = ?', [userId], (err) => {
                if (err) {
                    return res.status(500).json({
                        message: "Failed to clean up reset token",
                        status: 500,
                        error: "Internal Server Error",
                        response: null
                    });
                }

                res.status(200).json({
                    message: "Password reset successful",
                    status: 200,
                    error: null,
                    response: null
                });

            });
        });
    });
});

// Middleware Customer or Manager
function isCustomerOrManager(req, res, next) {
    if (req.session.role === 'customer' || req.session.role === 'manager') {
        return next();
    }
    res.status(403).json({ 
        message: "Access denied",
        status: 401,
        error: "Unauthorized",
        response: null
    });
}

// AVAILABILITY
app.get('/availability', isCustomerOrManager, (req, res) => {
    const today = new Date();
    const endDate = new Date();
    today.setDate(today.getDate() + 1);
    endDate.setDate(today.getDate() + 7); // Maksimal seminggu ke depan

    const startDateStr = today.toISOString().split('T')[0];
    const endDateStr = endDate.toISOString().split('T')[0];

    const availableSlots = [];

    db.query('SELECT * FROM courts WHERE is_active = 1', (err, courts) => {
        if (err) {
            return res.status(500).json({ 
                message: "Error fetching courts",
                status: 500,
                error: "Internal Server Error",
                response: null
            });
        }

        let pending = courts.length;
        if (pending === 0) {
            return res.status(200).json({ 
                message: "Showing all available slots",
                status: 200,
                error: null,
                response: { availability: [] }
            });
        }

        courts.forEach(court => {
            const courtId = court.id;
            const courtName = court.name;
            const openHour = parseInt(court.open_time.split(':')[0]);
            const closeHour = parseInt(court.close_time.split(':')[0]);

            db.query(
                'SELECT booking_date, booking_time, booking_duration FROM bookings WHERE court_id = ? AND status = "paid" AND booking_date BETWEEN ? AND ?',
                [courtId, startDateStr, endDateStr],
                (err, bookings) => {
                    if (err) {
                        return res.status(500).json({ 
                            message: "Error fetching bookings",
                            status: 500,
                            error: "Internal Server Error",
                            response: null
                        });
                    }

                    const bookedMap = {};
                    bookings.forEach(b => {
                        const date = new Date(b.booking_date); // Wed Apr 16 2025 00:00:00 GMT+0700
                        const year = date.getFullYear();
                        const month = String(date.getMonth() + 1).padStart(2, '0'); // bulan dimulai dari 0
                        const day = String(date.getDate()).padStart(2, '0');
                        const dateKey = `${year}-${month}-${day}`;
                        const startHour = parseInt(b.booking_time.slice(0, 2));
                        const durationHours = Math.ceil(b.booking_duration / 60);

                        if (!bookedMap[dateKey]) bookedMap[dateKey] = new Set();

                        for (let h = 0; h < durationHours; h++) {
                            const bookedHour = (startHour + h).toString().padStart(2, '0') + ":00";
                            bookedMap[dateKey].add(bookedHour);
                        }
                    });

                    const courtSlots = [];
                    for (let i = 0; i <= 7; i++) {
                        const date = new Date();
                        date.setDate(today.getDate() + i);
                        const dateStr = date.toISOString().split('T')[0];

                        for (let hour = openHour; hour < closeHour; hour++) {
                            const timeStr = `${hour.toString().padStart(2, '0')}:00`;

                            const isBooked = bookedMap[dateStr]?.has(timeStr);
                            if (!isBooked) {
                                courtSlots.push({
                                    court_id: courtId,
                                    court_type: courtName,
                                    date: dateStr,
                                    available_time: timeStr
                                });
                            }
                        }
                    }

                    availableSlots.push(...courtSlots);
                    pending--;
                    if (pending === 0) {
                        const grouped = {};

                        availableSlots.forEach(slot => {
                            const key = `${slot.court_id}_${slot.date}`;
                            if (!grouped[key]) {
                                grouped[key] = {
                                    court_id: slot.court_id,
                                    court_type: slot.court_type,
                                    date: slot.date,
                                    available_times: []
                                };
                            }
                            grouped[key].available_times.push(slot.available_time);
                        });

                        const groupedAvailability = Object.values(grouped);

                        res.status(200).json({ 
                            message: "Showing all available slots",
                            status: 200,
                            error: null,
                            response: { availability: groupedAvailability }
                        });
                    }
                }
            );
        });
    });
});

// Middleware Customer
function isCustomer(req, res, next) {
    if (!req.session.userId || req.session.role !== 'customer') {
        return res.status(403).json({
            message: "Access denied",
            status: 403,
            error: "Forbidden",
            response: null
        });
    }
    next();
}

// BOOK SLOT
app.post('/book_slot', isCustomer, (req, res) => {
    const { court_id, booking_date, booking_time, booking_duration } = req.body;

    if (!court_id || !booking_date || !booking_time || !booking_duration) {
        return res.status(400).json({
            message: "Court ID, Booking date, booking time, and booking duration are required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    const userId = req.session.userId;
    const ratePerHour = 100000;
    const payment_amount = Math.ceil(booking_duration / 60) * ratePerHour;

    // Step 1: Validasi lapangan
    db.query(
        'SELECT * FROM courts WHERE id = ?',
        [court_id],
        (err, courts) => {
            if (err || courts.length === 0) {
                return res.status(404).json({
                    message: "Court not found",
                    status: 404,
                    error: "Not Found",
                    response: null
                });
            }

            const court = courts[0];

            if (!court.is_active) {
                return res.status(403).json({
                    message: "Court is currently inactive (e.g. under maintenance)",
                    status: 403,
                    error: "Forbidden",
                    response: null
                });
            }

            const bookingTime = booking_time;
            const openTime = court.open_time.slice(0, 5); // HH:MM
            const closeTime = court.close_time.slice(0, 5); // HH:MM

            if (bookingTime < openTime || bookingTime >= closeTime) {
                return res.status(403).json({
                    message: `Booking time must be within operational hours (${openTime} - ${closeTime})`,
                    status: 403,
                    error: "Forbidden",
                    response: null
                });
            }

            // Step 2: Cek slot sudah dibooking?
            db.query(
                'SELECT * FROM bookings WHERE court_id = ? AND booking_date = ? AND booking_time = ? AND status = "paid"',
                [court_id, booking_date, booking_time],
                (err, results) => {
                    if (err) {
                        return res.status(500).json({
                            message: "Error checking booking slot",
                            status: 500,
                            error: "Internal Server Error",
                            response: null
                        });
                    }

                    if (results.length > 0) {
                        return res.status(409).json({
                            message: "Slot already booked",
                            status: 409,
                            error: "Conflict",
                            response: null
                        });
                    }

                    // Step 3: Insert booking
                    db.query(
                        'INSERT INTO bookings (user_id, court_id, booking_date, booking_time, booking_duration, payment_amount, status) VALUES (?, ?, ?, ?, ?, ?, "pending")',
                        [userId, court_id, booking_date, booking_time, booking_duration, payment_amount],
                        (err, result) => {
                            if (err) {
                                return res.status(500).json({
                                    message: "Failed to create booking",
                                    status: 500,
                                    error: "Internal Server Error",
                                    response: null
                                });
                            }

                            const bookingId = result.insertId;

                            // Auto-cancel booking dalam 10 menit jika belum dibayar
                            setTimeout(() => {
                                db.query(
                                    'SELECT status FROM bookings WHERE id = ?',
                                    [bookingId],
                                    (err, results) => {
                                        if (err || results.length === 0) return;
                                        if (results[0].status === 'pending') {
                                            db.query(
                                                'UPDATE bookings SET status = "cancelled" WHERE id = ?',
                                                [bookingId]
                                            );
                                        }
                                    }
                                );
                            }, 10 * 60 * 1000); // 10 menit

                            res.status(201).json({
                                message: "Booking created. Awaiting payment confirmation...",
                                status: 201,
                                error: null,
                                response: {
                                    bookingId,
                                    payment_amount
                                }
                            });
                        }
                    );
                }
            );
        }
    );
});

// PAYMENT
app.post('/payment', isCustomer, (req, res) => {
    const { booking_id, payment_status, amount, payment_method } = req.body;

    if (!booking_id || !payment_status || !amount || !payment_method) {
        return res.status(400).json({
            message: "Booking ID, payment status, payment amount, and payment method are required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    db.query('SELECT user_id, payment_amount, status FROM bookings WHERE id = ?', [booking_id], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({
                message: "Booking not found",
                status: 404,
                error: "Not found",
                response: null
            });
        } 

        const { user_id, payment_amount, status } = results[0];

        if (status !== 'pending') {
            return res.status(400).json({
                message: "Payment already processed or booking cancelled",
                status: 400,
                error: "Bad Request",
                response: null
            });
        }

        if (payment_status === 'success' && payment_amount === amount) {
            
            db.query(
                'UPDATE bookings SET status = "paid", payment_method = ? WHERE id = ?',
                [payment_method, booking_id],
                (err) => {
                    if (err) {
                        return res.status(500).json({
                            message: "Failed to update booking",
                            status: 500,
                            error: "Internal Server Error",
                            response: null
                        });
                    }

                    db.query(
                        'INSERT INTO transactions (booking_id, user_id, payment_amount, payment_method) VALUES (?, ?, ?, ?)',
                        [booking_id, user_id, payment_amount, payment_method],
                        (err) => {
                            if (err) {
                                return res.status(500).json({
                                    message: "Failed to create transaction",
                                    status: 500,
                                    error: "Internal Server Error",
                                    response: null
                                });
                            }
                            res.status(201).json({
                                message: "Payment confirmed and transaction recorded",
                                status: 201,
                                error: null,
                                response: { booking_id, amount, payment_method }
                            });
                        }
                    );
                }
            );
        } else {
            db.query('UPDATE bookings SET status = "cancelled" WHERE id = ?', [booking_id], (err) => {
                if (err) {
                    return res.status(500).json({
                        message: "Failed to cancel booking",
                        status: 500,
                        error: "Internal Server Error",
                        response: null
                    });
                }
                res.status(201).json({
                    message: "Payment failed, booking cancelled",
                    status: 201,
                    error: null,
                    response: { booking_id, amount, payment_method }
                });
            });
        }
    });
});

// MY BOOKINGS
app.get('/my_bookings', isCustomer, (req, res) => {
    const userId = req.session.userId;

    db.query(
        'SELECT * FROM bookings WHERE user_id = ? ORDER BY booking_date DESC, booking_time DESC',
        [userId],
        (err, results) => {
            if (err) {
                return res.status(500).json({
                    message: "Failed to retrieve bookings",
                    status: 500,
                    error: "Internal Server Error",
                    response: null
                });
            }
            res.status(200).json({
                message: "Showing my bookings",
                status: 200,
                error: null,
                response: { results }
            });
        }
    );
});

// Middleware Manager
function isManager(req, res, next) {
    if (!req.session.userId || req.session.role !== 'manager') {
        return res.status(403).json({
            message: "Access denied",
            status: 403,
            error: "Forbidden",
            response: null
        });
    }
    next();
}

// ADD COURTS
app.post('/add_courts', isManager, (req, res) => {
    const { court_type, open_time, close_time } = req.body;

    if (!court_type || !open_time || !close_time) {
        return res.status(400).json({
            message: "Court type, open time, and close time are required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    db.query(
        'INSERT INTO courts (court_type, open_time, close_time, is_active) VALUES (?, ?, ?, 1)',
        [court_type, open_time, close_time],
        (err, result) => {
            if (err) {
                return res.status(500).json({
                    message: "Failed to add court",
                    status: 500,
                    error: "Internal Server Error",
                    response: null
                });
            }

            res.status(201).json({
                message: "Court added successfully",
                status: 201,
                error: null,
                response: { court_type, open_time, close_time }
            });
        }
    );
});

// UPDATE COURTS STATUS
app.patch('/update_courts/:id/status', isManager, (req, res) => {
    const courtId = req.params.id;
    const { is_active } = req.body;

    if (typeof is_active !== 'boolean') {
        return res.status(400).json({
            message: "is_active must be a boolean (true/false)",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    db.query(
        'UPDATE courts SET is_active = ? WHERE id = ?',
        [is_active ? 1 : 0, courtId],
        (err, result) => {
            if (err) {
                return res.status(500).json({
                    message: "Failed to update court status",
                    status: 500,
                    error: "Internal Server Error",
                    response: null
                });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    message: "Court not found",
                    status: 404,
                    error: "Not Found",
                    response: null
                });
            }

            res.status(200).json({
                message: `Court status updated successfully'}`,
                status: 200,
                error: null,
                response: { courtId, is_active }
            });
        }
    );
});

// UPDATE COURTS OPERATION HOURS
app.patch('/update_courts/:id/operation_hours', isManager, (req, res) => {
    const courtId = req.params.id;
    const { open_time, close_time } = req.body;

    if (!open_time || !close_time) {
        return res.status(400).json({
            message: "Open time and close time are required",
            status: 400,
            error: "Bad Request",
            response: null
        });
    }

    db.query(
        'UPDATE courts SET open_time = ?, close_time = ? WHERE id = ?',
        [open_time, close_time, courtId],
        (err, result) => {
            if (err) {
                return res.status(500).json({
                    message: "Failed to update operation hours",
                    status: 500,
                    error: "Internal Server Error",
                    response: null
                });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    message: "Court not found",
                    status: 404,
                    error: "Not Found",
                    response: null
                });
            }

            res.status(200).json({
                message: "Court operation hours updated successfully",
                status: 200,
                error: null,
                response: { courtId, open_time, close_time }
            });
        }
    );
});

// TRANSACTIONS
app.get('/transactions_report', isManager, (req, res) => {
    db.query(
        'SELECT t.*, u.username, b.booking_date, b.booking_time FROM transactions t JOIN users u ON t.user_id = u.id JOIN bookings b ON t.booking_id = b.id',
        (err, results) => {
            if (err) {
                return res.status(500).json({
                    message: "Failed to retrieve transactions",
                    status: 500,
                    error: "Internal Server Error",
                    response: null
                });
            }
            res.status(200).json({
                message: "Showing all transactions",
                status: 200,
                error: null,
                response: { results }
            });
        }
    );
});

// TOTAL INCOME
app.get('/total_income', isManager, (req, res) => {
    db.query('SELECT SUM(payment_amount) AS total_income FROM transactions', (err, results) => {
        if (err) {
            return res.status(500).json({
                message: "Failed to calculate income",
                status: 500,
                error: "Internal Server Error",
                response: null
            });
        }
        res.status(200).json({
            message: "Showing all total income",
            status: 200,
            error: null,
            response: { total_income: results[0].total_income || 0 }
        });
    });
});

// START SERVER
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));