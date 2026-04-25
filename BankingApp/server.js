const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./database/db');
const app = express();
const PORT = 5090;

app.use(express.json());
app.use(express.static('Public'));

// Session management
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ message: 'Unauthorized' });
    }
}

// Register a new user
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (row) {
            return res.status(400).json({ message: 'User already exists.' });
        }

        db.run('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword], (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error registering user.' });
            }
            res.json({ message: 'Registration successful!' });
        });
    });
});

// Login an existing user
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
        if (!row || !(await bcrypt.compare(password, row.password))) {
            return res.status(400).json({ message: 'Invalid email or password.' });
        }

        req.session.user = { email: row.email, id: row.id };
        res.json({ message: 'Login successful!' });
    });
});

// Deposit money
app.post('/deposit', isAuthenticated, (req, res) => {
    const { amount } = req.body;
    const email = req.session.user.email;

    db.run('UPDATE users SET balance = balance + ? WHERE email = ?', [amount, email], (err) => {
        if (err) {
            return res.status(500).json({ message: 'Error depositing funds.' });
        }
        res.json({ message: `Deposit of $${amount.toFixed(2)} CAD successful!` });
    });
});

// Withdraw money
app.post('/withdraw', isAuthenticated, (req, res) => {
    const { amount } = req.body;
    const email = req.session.user.email;

    db.get('SELECT balance FROM users WHERE email = ?', [email], (err, row) => {
        if (row.balance < amount) {
            return res.status(400).json({ message: 'Insufficient funds.' });
        }

        db.run('UPDATE users SET balance = balance - ? WHERE email = ?', [amount, email], (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error withdrawing funds.' });
            }
            res.json({ message: `Withdrawal of $${amount.toFixed(2)} CAD successful!` });
        });
    });
});

// Check balance
app.get('/balance', isAuthenticated, (req, res) => {
    const email = req.session.user.email;

    db.get('SELECT balance FROM users WHERE email = ?', [email], (err, row) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching balance.' });
        }
        res.json({ balance: row.balance });
    });
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Error logging out.' });
        }
        res.json({ message: 'Logout successful!' });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});