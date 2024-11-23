const express = require('express');
const { Keypair, Connection, PublicKey, clusterApiUrl, SystemProgram, Transaction } = require('@solana/web3.js');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your_jwt_secret_key'; // Replace with a secure secret in production
const WALLET_DB_FILE = path.join(__dirname, 'wallets.json');
const USERS_DB_FILE = path.join(__dirname, 'users.json');

// Solana connection
const connection = new Connection(clusterApiUrl('mainnet-beta'), 'confirmed');

// Load wallets and users from files
let userWallets = fs.existsSync(WALLET_DB_FILE)
    ? JSON.parse(fs.readFileSync(WALLET_DB_FILE, 'utf8'))
    : {};

let users = fs.existsSync(USERS_DB_FILE)
    ? JSON.parse(fs.readFileSync(USERS_DB_FILE, 'utf8'))
    : {};

// Save wallets to file
function saveWalletsToFile() {
    fs.writeFileSync(WALLET_DB_FILE, JSON.stringify(userWallets, null, 2));
}

// Save users to file
function saveUsersToFile() {
    fs.writeFileSync(USERS_DB_FILE, JSON.stringify(users, null, 2));
}

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend')));

// Authentication middleware
function authenticateToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// User registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    if (users[username]) {
        return res.status(400).json({ error: 'Username already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user and wallet
    users[username] = { username, password: hashedPassword };
    const keypair = Keypair.generate();
    userWallets[username] = {
        publicKey: keypair.publicKey.toString(),
        secretKey: Array.from(keypair.secretKey),
        balance: 0, // Initial balance
    };

    saveUsersToFile();
    saveWalletsToFile();

    res.json({ message: 'Registration successful!' });
});

// User login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    const user = users[username];
    if (!user) {
        return res.status(400).json({ error: 'Invalid username or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(400).json({ error: 'Invalid username or password.' });
    }

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: 'Login successful!', token });
});

// Get wallet information
app.get('/wallet', authenticateToken, (req, res) => {
    const { username } = req.user;
    const wallet = userWallets[username];

    if (!wallet) {
        return res.status(404).json({ error: 'Wallet not found.' });
    }

    res.json({ publicKey: wallet.publicKey });
});

// Get wallet balance
app.get('/balance', authenticateToken, async (req, res) => {
    const { username } = req.user;
    const wallet = userWallets[username];
    const publicKey = new PublicKey(wallet.publicKey);

    try {
        const balance = await connection.getBalance(publicKey);
        res.json({ balance: balance / 1e9 });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch balance.' });
    }
});

// Withdraw SOL
app.post('/withdraw', authenticateToken, async (req, res) => {
    const { username } = req.user;
    const { recipient, amount } = req.body;

    const wallet = userWallets[username];
    if (!wallet || wallet.balance < amount) {
        return res.status(400).json({ error: 'Insufficient balance.' });
    }

    const senderKeypair = Keypair.fromSecretKey(Uint8Array.from(wallet.secretKey));
    const transaction = new Transaction().add(
        SystemProgram.transfer({
            fromPubkey: senderKeypair.publicKey,
            toPubkey: new PublicKey(recipient),
            lamports: amount * 1e9,
        })
    );

    try {
        const signature = await connection.sendTransaction(transaction, [senderKeypair]);
        await connection.confirmTransaction(signature);

        wallet.balance -= amount;
        saveWalletsToFile();

        res.json({ message: 'Withdrawal successful!', signature });
    } catch (error) {
        res.status(500).json({ error: 'Failed to process withdrawal.' });
    }
});

// Serve the frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
