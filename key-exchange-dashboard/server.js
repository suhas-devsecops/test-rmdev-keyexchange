const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt'); // keep bcrypt only
const crypto = require('crypto');
const cron = require('node-cron');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Postgres connection
const pool = new Pool({
  user: 'admin',
  host: '172.174.230.197',
  database: 'webkeyexchange',
  password: 'adminpass',
  port: 5432,
});

// Create tables if not exists
pool.query(`
  CREATE TABLE IF NOT EXISTS requests (
    id SERIAL PRIMARY KEY,
    fullname TEXT NOT NULL,
    email TEXT NOT NULL,
    contact TEXT NOT NULL,
    wireguardkey TEXT NOT NULL,
    pgpkey TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_timestamp TIMESTAMP DEFAULT NULL
  );
  CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    fullname TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    contact TEXT NOT NULL,
    project TEXT,
    password TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS server_keys (
    id SERIAL PRIMARY KEY,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    expiry TIMESTAMP NOT NULL,
    user_type TEXT DEFAULT 'client'
  );
  CREATE TABLE IF NOT EXISTS client_otps (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES clients(id),
    otp TEXT NOT NULL,
    expiry TIMESTAMP NOT NULL
  );
  CREATE TABLE IF NOT EXISTS activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    user_type TEXT NOT NULL CHECK (user_type IN ('admin', 'client')),
    action TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    fullname VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    team VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`).then(() => console.log('Tables ready'))
  .catch(err => console.error('Table creation error:', err));

async function logActivity(userId, userType, action) {
  try {
    await pool.query(
      'INSERT INTO activity_logs (user_id, user_type, action) VALUES ($1, $2, $3)',
      [userId, userType, action]
    );
  } catch (err) {
    console.error('Activity log error:', err);
  }
}

async function cleanupExpired(pool) {
// Delete OTPs older than 10 minutes
await pool.query("DELETE FROM client_otps WHERE expiry < NOW() - INTERVAL '10 minutes'");
// Delete reset tokens older than 10 minutes
await pool.query("DELETE FROM password_reset_tokens WHERE expiry < NOW() - INTERVAL '10 minutes'");
}

// NEW: Cleanup expired OTPs and reset tokens (deletes records older than 10 minutes)
app.post('/cleanup-expired', async (req, res) => {
  try {
    await cleanupExpired(pool);
    res.json({ message: 'Expired records cleaned up' });
  } catch (err) {
    console.error('Cleanup error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Submit request (updated with wireguardkey and pgpkey)
app.post('/submit-request', async (req, res) => {
  const { fullname, email, contact, wireguardkey, pgpkey } = req.body;
  if (!fullname || !email || !contact || !wireguardkey) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    await pool.query(
      'INSERT INTO requests (fullname, email, contact, wireguardkey, pgpkey, status) VALUES ($1, $2, $3, $4, $5, $6)',
      [fullname, email, contact, wireguardkey, pgpkey, 'pending']
    );
    res.status(201).json({ message: 'Request submitted successfully' });
  } catch (err) {
    console.error('Insert error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Client signup (updated to check uniqueness)
app.post('/client-signup', async (req, res) => {
  const { fullname, email, contact, project } = req.body;
  if (!fullname || !email || !contact) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    // Check for existing fullname or email
    const checkResult = await pool.query(
      'SELECT id FROM clients WHERE fullname = $1 OR email = $2',
      [fullname, email]
    );
    if (checkResult.rows.length > 0) {
      return res.status(409).json({ error: 'Username (fullname) or email already in use' });
    }

    await pool.query(
      'INSERT INTO clients (fullname, email, contact, project, status) VALUES ($1, $2, $3, $4, $5)',
      [fullname, email, contact, project, 'pending']
    );
    res.status(201).json({ message: 'Signup submitted. Awaiting admin approval.' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get all submitted requests (for client)
app.get('/submitted-requests', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM requests ORDER BY timestamp DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get pending requests (for admin)
app.get('/pending-requests', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM requests WHERE status = 'pending' ORDER BY timestamp DESC");
    res.json(result.rows);
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get completed requests (for admin)
app.get('/completed-requests', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM requests WHERE status IN ('approved', 'cancelled') ORDER BY updated_timestamp DESC");
    res.json(result.rows);
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get approved users (for KeyExchange)
app.get('/approved-users', async (req, res) => {
  try {
    const result = await pool.query("SELECT id, fullname, email, wireguardkey, pgpkey, updated_timestamp FROM requests WHERE status = 'approved' ORDER BY updated_timestamp DESC");
    res.json(result.rows);
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get all clients (for admin)
app.get('/clients', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clients ORDER BY timestamp DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get pending clients (for admin)
app.get('/pending-clients', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM clients WHERE status = 'pending' ORDER BY timestamp DESC");
    res.json(result.rows);
  } catch (err) {
    console.error('Query error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get activity logs (for admin viewing)
app.get('/activity-logs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM activity_logs ORDER BY timestamp DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Query logs error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Approve a request
app.post('/approve-request/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("UPDATE requests SET status = 'approved', updated_timestamp = CURRENT_TIMESTAMP WHERE id = $1", [id]);
    res.json({ message: 'Request approved' });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Cancel a request
app.post('/cancel-request/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("UPDATE requests SET status = 'cancelled', updated_timestamp = CURRENT_TIMESTAMP WHERE id = $1", [id]);
    res.json({ message: 'Request cancelled' });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Approve a client (with email sending for password setup)
app.post('/approve-client/:id', async (req, res) => {
  const { id } = req.params;
  try {
    // Update status to approved
    await pool.query("UPDATE clients SET status = 'approved' WHERE id = $1", [id]);


    // Generate token
    const token = uuidv4();
    const expiry = new Date(Date.now() + 15 * 60 * 1000);  // 15 minutes expiry


    // Store token
    await pool.query('INSERT INTO password_reset_tokens (user_id, token, expiry, user_type) VALUES ($1, $2, $3, $4)',[id, token, expiry, 'client']);


    // Get user email and fullname
    const userResult = await pool.query('SELECT email, fullname FROM clients WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const { email, fullname } = userResult.rows[0];


    // Send email with password setup link
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'suhas@saturam.com',   // Your  Gmail username/email
        pass: 'wpzwhhqjxqivyxsp' // Generate from Google Account settings
      }
    });


    const mailOptions = {
      from: 'Admin <admin@webkeyexchange.com>',  // Display name and your Gmail address
      to: email,
      subject: 'Client Account Approved - Set Your Password',
      text: `Dear ${fullname},\n\nYour Client Account has been approved. Please set your password by clicking this link (valid for 10minutes):\nhttp://172.174.230.197:3000/set-password.html?token=${token}&userId=${id}\n\nBest regards,\nAdmin`
    };


    await transporter.sendMail(mailOptions);

    // Log the action (assuming admin ID is 0 or pass it via req if available)
    await logActivity(0, 'admin', `Approved client user ID: ${id}`);

    res.json({ message: 'Client approved and email sent' });
  } catch (err) {
    console.error('Approval error:', err);
    res.status(500).json({ error: 'Database or email error' });
  }
});

// Set password (log the action)
app.post('/set-password', async (req, res) => {
  const { token, userId, password } = req.body;
  if (!token || !userId || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const tokenResult = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE user_id = $1 AND token = $2 AND expiry > CURRENT_TIMESTAMP',
      [userId, token]
    );
    if (tokenResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }


    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE clients SET password = $1 WHERE id = $2', [hashedPassword, userId]);
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1 AND token = $2', [userId, token]);

    // Log the action
    await logActivity(userId, 'client', 'Password set/reset successfully');

    res.json({ message: 'Password set successfully' });
  } catch (err) {
    console.error('Set password error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Share server's public key as encrypted text file (using WireGuard key as password)
app.post('/share-key', async (req, res) => {
  const { userIds } = req.body;
  if (!userIds || userIds.length === 0) {
    return res.status(400).json({ error: 'Missing user IDs' });
  }

  try {
    // Fetch server's public key from DB
    const keyResult = await pool.query('SELECT public_key FROM server_keys ORDER BY created_at DESC LIMIT 1');
    if (keyResult.rows.length === 0) {
      return res.status(500).json({ error: 'Server public key not found in DB' });
    }
    const serverPublicKey = keyResult.rows[0].public_key;

    // Fetch selected users' details (include wireguardkey for password)
    const userResult = await pool.query(
      "SELECT id, fullname, email, wireguardkey FROM requests WHERE id = ANY($1) AND status = 'approved'",
      [userIds]
    );
    const users = userResult.rows;

    if (users.length === 0) {
      return res.status(404).json({ error: 'No approved users found' });
    }

    // Nodemailer transporter with Gmail
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'suhas@saturam.com',   // Your  Gmail username/email
        pass: 'wpzwhhqjxqivyxsp' // Generate from Google Account settings
      }
    });

    let sentCount = 0;
    for (const user of users) {
      try {
        if (!user.wireguardkey) {
          console.warn(`Skipping user ${user.id} (${user.email}): No WireGuard key available for encryption`);
          continue;
        }

        // Message content (server key)
        const message = `Server WireGuard Public Key:\n${serverPublicKey}`;

        // Encrypt using user's WireGuard key as password (AES-256-CBC)
        const password = user.wireguardkey;
        const salt = crypto.randomBytes(16);
        const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(message, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        // Create encrypted file content (with salt and IV for decryption)
        const encryptedData = `Salt: ${salt.toString('hex')}\nIV: ${iv.toString('hex')}\nEncrypted: ${encrypted}`;

        // Send email with encrypted attachment
        await transporter.sendMail({
          from: 'Admin <admin@webkeyexchange.com>',
          to: user.email,
          subject: 'Approved: Encrypted Server WireGuard Public Key Access',
          text: `Dear ${user.fullname},\n\nYour request has been approved.\nPlease find the server WireGuard public key attached as an encrypted text file.\n\nTo decrypt it, use your WireGuard key as the password.\n You can visit the Client Dashboard, upload the file, and decrypt it by entering the password  under the "Decrypt" tab.\n\nBest regards,\nAdmin`,
          attachments: [{
            filename: 'server_key.encrypted.txt',
            content: encryptedData
          }]
        });

        console.log(`Encrypted email sent to ${user.email}`);
        sentCount++;
      } catch (innerErr) {
        console.error(`Error processing user ${user.id} (${user.email}):`, innerErr.message);
        // Continue to next user
      }
    }

    res.json({ message: `Public key shared successfully to ${sentCount} users` });
  } catch (err) {
    console.error('Error sharing key:', err);
    res.status(500).json({ error: 'Failed to share key: ' + err.message });
  }
});

// NEW: Admin resets client password (sends reset link to client)
app.post('/reset-client-password/:id', async (req, res) => {
  const { id } = req.params;
  try {
    // Get user email and fullname
    const userResult = await pool.query('SELECT email, fullname FROM clients WHERE id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const { email, fullname } = userResult.rows[0];

    // Generate token
    const token = uuidv4();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);  // 10 minutes expiry

    // Store token (overwrite any existing for this user)
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [id]); // Clear old tokens
    await pool.query('INSERT INTO password_reset_tokens (user_id, token, expiry) VALUES ($1, $2, $3,$4)', [id, token, expiry,'client']);

    // Send email with reset link
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'suhas@saturam.com',   // Your  Gmail username/email
        pass: 'wpzwhhqjxqivyxsp' // Generate from Google Account settings
      }
    });

    const mailOptions = {
      from: 'Admin <admin@webkeyexchange.com>',
      to: email,
      subject: 'Password Reset Request',
      text: `Dear ${fullname},\n\nThe admin has requested a password reset for your account. Please set a new password using this link (valid for 1o minutes):\nhttp://172.174.230.197:3000/set-password.html?token=${token}&userId=${id}\n\nBest regards,\nAdmin`
    };

    await transporter.sendMail(mailOptions);

    // Log the action (assuming admin user ID is 0; adjust if you have admin authentication)
    await logActivity(0, 'admin', `Initiated password reset for client ID: ${id}`);

    res.json({ message: 'Reset email sent to client' });
  } catch (err) {
    console.error('Reset error:', err);
    res.status(500).json({ error: 'Database or email error' });
  }
});

// Client login (updated to support email OR fullname, OTP 2 min expiry)
app.post('/client-login', async (req, res) => {
  const { login, password } = req.body;  // 'login' can be email or fullname
  if (!login || !password) {
    return res.status(400).json({ error: 'Missing login or password' });
  }
  try {
    const userResult = await pool.query(
      'SELECT id, password FROM clients WHERE (email = $1 OR fullname = $1) AND status = $2',
      [login, 'approved']
    );
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials or account not approved' });
    }
    const user = userResult.rows[0];

    if (!user.password) {
      return res.status(401).json({ error: 'No password set for this account. Please reset your password.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 2 * 60 * 1000);  // 2 minutes validity

    // Store OTP
    await pool.query('INSERT INTO client_otps (user_id, otp, expiry) VALUES ($1, $2, $3)', [user.id, otp, expiry]);

    // Send OTP email (fetch email from DB since login could be fullname)
    const emailResult = await pool.query('SELECT email FROM clients WHERE id = $1', [user.id]);
    const email = emailResult.rows[0].email;

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'suhas@saturam.com',   // Your  Gmail username/email
        pass: 'wpzwhhqjxqivyxsp' // Generate from Google Account settings
      }
    });

    const mailOptions = {
      from: 'Admin <admin@webkeyexchange.com>',
      to: email,
      subject: 'Your One-Time Password (OTP) for Client Login',
      text: `Your one-time password (OTP) for login is: ${otp}\nIt will remain valid for the next 2 minutes.\n\nKind regards,\nAdmin`
    };

    await transporter.sendMail(mailOptions);

    // Log the action
    await logActivity(user.id, 'client', 'Login attempt: OTP sent');

    res.json({ message: 'OTP sent to email', userId: user.id });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Database or email error' });
  }
});

// Client verify OTP (unchanged from previous)
app.post('/client-verify-otp', async (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp) {
    return res.status(400).json({ error: 'Missing userId or OTP' });
  }
  try {
    const otpResult = await pool.query(
      'SELECT * FROM client_otps WHERE user_id = $1 AND otp = $2 AND expiry > CURRENT_TIMESTAMP',
      [userId, otp]
    );
    if (otpResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Delete used OTP
    await pool.query('DELETE FROM client_otps WHERE user_id = $1 AND otp = $2', [userId, otp]);

    // Log the action
    await logActivity(userId, 'client', 'OTP verified successfully');

    res.json({ message: 'OTP verified successfully' });
  } catch (err) {
    console.error('OTP verification error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});


// NEW: Delete a client user by ID
app.delete('/delete-client/:id', async (req, res) => {
  const { id } = req.params;
  try {
    // Delete the user and return the deleted row (if exists)
    const result = await pool.query('DELETE FROM clients WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Client user not found' });
    }
    // Optionally, clean up related data (e.g., tokens)
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [id]);
    await pool.query('DELETE FROM client_otps WHERE user_id = $1', [id]);  // If using OTP table

    // Related data is auto-deleted via ON DELETE CASCADE

    // Log the action (assuming admin ID is 0)
    await logActivity(0, 'admin', `Deleted client user ID: ${id}`);

    res.json({ message: 'Client user deleted successfully' });
  } catch (err) {
    console.error('Delete client error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});


// Get activity logs (for admin viewing)
app.get('/activity-logs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM activity_logs ORDER BY timestamp DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Query logs error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ---------- INSERT ADMIN USERS FEATURE HERE ----------
app.post('/add-admin', async (req, res) => {
  const { fullname, email, team } = req.body;
  if (!fullname || !email || !team) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const exists = await pool.query(
      'SELECT 1 FROM admins WHERE fullname = $1 OR email = $2',
      [fullname, email]
    );
    if (exists.rows.length > 0) {
      return res.status(409).json({ error: 'Fullname or email exists' });
    }

    // ✅ Insert once, no status column
    const ins = await pool.query(
      'INSERT INTO admins (fullname, email, team) VALUES ($1, $2, $3) RETURNING id, fullname, email, created_at',
      [fullname, email, team]
    );
    const admin = ins.rows[0];

    const token = uuidv4();
    const expiry = new Date(Date.now() + 15 * 60 * 1000);

    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expiry, user_type) VALUES ($1, $2, $3, $4)',
      [admin.id, token, expiry, 'admin']
    );

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: 'suhas@saturam.com', pass: 'wpzwhhqjxqivyxsp' }
    });

    const link = `http://172.174.230.197:3000/set-password.html?token=${token}&userId=${admin.id}&type=admin`;
    await transporter.sendMail({
      from: 'Admin <admin@webkeyexchange.com>',
      to: admin.email,
      subject: 'Set Your Admin Password',
      text: `Dear ${admin.fullname},\n\nPlease set your admin password here (valid 15 mins):\n${link}\n\nBest Regards,\nAdmin`
    });

    await logActivity(0, 'admin', `Created admin ID: ${admin.id}`);
    res.json({ message: 'Admin created and email sent' });
  } catch (err) {
    console.error('Add admin error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/all-admins', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM admins ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/reset-admin-password/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const r = await pool.query('SELECT fullname, email FROM admins WHERE id = $1', [id]);
    if (r.rows.length === 0) return res.status(404).json({ error: 'Admin not found' });

    const { fullname, email } = r.rows[0];
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1 AND user_type = $2', [id, 'admin']);

    const token = uuidv4();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token, expiry, user_type) VALUES ($1, $2, $3, $4)',
      [id, token, expiry, 'admin']
    );


    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: 'suhas@saturam.com', pass: 'wpzwhhqjxqivyxsp' }
    });
    const link = `http://172.174.230.197:3000/set-password.html?token=${token}&userId=${id}&type=admin`;
    await transporter.sendMail({
      from: 'Admin <admin@webkeyexchange.com>',
      to: email,
      subject: 'Admin Password Reset',
      text: `Dear ${fullname},\n\nReset your password here (valid 10 mins):\n${link}\n\nBest Regards,\nAdmin`
    });

    await logActivity(0, 'admin', `Password reset for admin ID: ${id}`);
    res.json({ message: 'Reset email sent' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/delete-admin/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const del = await pool.query('DELETE FROM admins WHERE id = $1 RETURNING *', [id]);
    if (del.rowCount === 0) return res.status(404).json({ error: 'Admin not found' });

    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1 AND user_type = $2', [id, 'admin']);
    await logActivity(0, 'admin', `Deleted admin ID: ${id}`);
    res.json({ message: 'Admin deleted' });
  } catch (err) {
    res.status(500).json({ error: 'DB error' });
  }
});

// Update set-password to support admins
app.post('/set-password', async (req, res) => {
  const { token, userId, password } = req.body;
  if (!token || !userId || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    // Must retrieve user_type with the token
    const t = await pool.query(
      'SELECT user_type FROM password_reset_tokens WHERE user_id = $1 AND token = $2 AND expiry > CURRENT_TIMESTAMP',
      [userId, token]
    );
    if (t.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const userType = t.rows[0].user_type || 'client';
    const hashedPassword = await bcrypt.hash(password, 10);

    if (userType === 'admin') {
  await pool.query(
    'UPDATE admins SET hashed_password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
    [hashedPassword, userId]
  );
  await logActivity(userId, 'admin', 'Admin password set/reset successfully');
}

    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1 AND token = $2', [userId, token]);
    res.json({ message: 'Password set successfully' });
  } catch (err) {
    console.error('Set password error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});


// ---------- END ADMIN USERS FEATURE ----------

// Schedule cleanup every 10 minutes
cron.schedule('*/10 * * * *', async () => {
try {
await cleanupExpired(pool);
console.log('Expired records cleaned up (cron)');
} catch (err) {
console.error('Scheduled cleanup error:', err);
}
});

//app.listen(3000, () => console.log('Server running on http://localhost:3000'));
const HOST = '0.0.0.0';
const PORT = 3000;
app.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
