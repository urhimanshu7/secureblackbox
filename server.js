const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const bodyParser = require("body-parser");
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mime = require('mime'); // correct import

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB setup
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.error("MongoDB error:", err));


// User Schema
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  otpEmail: { type: String, required: true, unique: true }, 
  password: String,
  twoFactorPassword: String
});
const User = mongoose.model('User', UserSchema);

const FileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  filename: String,
  size: Number,
  uploadedAt: { type: Date, default: Date.now },
  views: { type: Number, default: 0 }
});
const File = mongoose.model('File', FileSchema);

// Middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, 'final-secret-key');
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Encryption utils
const secretKey = crypto.createHash('sha256').update('my-very-strong-secret-key').digest(); // persistent
const iv = Buffer.alloc(16, 0); // persistent

function encryptBuffer(buffer) {
  const cipher = crypto.createCipheriv('aes-256-cbc', secretKey, iv);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
}

function decryptBuffer(buffer) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', secretKey, iv);
  return Buffer.concat([decipher.update(buffer), decipher.final()]);
}

// Multer setup
const upload = multer({ dest: 'temp_uploads/' });

let otpStore = {}; // { email: otp }

// Gmail transporter
const transporter = nodemailer.createTransport({
  service: "gmail", 
  auth: {
    user: "secureblackbox7@gmail.com",
    pass: "wfggwakzhxcatypg" 
  }
});


// ------------------- REGISTER -------------------
app.post("/register", async (req, res) => {
  try {
    const { email, password, twoFactorPassword, otpEmail } = req.body;

    if (!email || !otpEmail || !password || !twoFactorPassword) {
      return res.status(400).json({ error: "All fields are required." });
    }

    // 1️⃣ Check: Email and Backup Email MUST NOT BE SAME
    if (email === otpEmail) {
      return res.status(400).json({ error: "Backup email must be different from main email." });
    }

    // 2️⃣ Check: Email already used?
    const user1 = await User.findOne({ email });
    if (user1) {
      return res.status(400).json({ error: "Email already registered." });
    }

    // 3️⃣ Check: Backup email already used?
    const user2 = await User.findOne({ otpEmail });
    if (user2) {
      return res.status(400).json({ error: "Backup email already registered by another user." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashed2FA = await bcrypt.hash(twoFactorPassword, 10);

    const newUser = new User({
      email,
      otpEmail,
      password: hashedPassword,
      twoFactorPassword: hashed2FA,
    });

    await newUser.save();

    res.status(201).json({ message: "User registered successfully." });

  } catch (err) {
    console.error("register error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ------------------- LOGIN -------------------

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

  const tempToken = jwt.sign({ userId: user._id }, 'temp-secret-key', { expiresIn: '5m' });
  res.json({ tempToken, otpEmail: user.otpEmail });
});

// ------------------- SEND OTP -------------------
app.post("/send-otp", async (req, res) => {
  try {
    const { email } = req.body; 
    if (!email) return res.status(400).json({ error: "Email required" });

    const user = await User.findOne({ otpEmail: email });
    if (!user) {
      return res.status(403).json({ error: "This is not a registered backup email." });
    }

    const backupEmail = user.otpEmail;

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000);
    const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

    otpStore[backupEmail] = { code: otp, expiresAt };

    const mailOptions = {
      from: '"Secure Box" <secureblackbox7@gmail.com>',
      to: backupEmail,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}. It will expire in 5 minutes.`,
      html: `<p>Your OTP is <b>${otp}</b>. It will expire in <b>5 minutes</b>.</p>`,
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("send-otp error:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// ------------------- VERIFY OTP -------------------
app.post("/verify-otp", async (req, res) => {
  try {
    const { otp, email } = req.body; 
    if (!otp || !email) return res.status(400).json({ error: "OTP and email required" });

    const user = await User.findOne({ otpEmail: email });
    if (!user) return res.status(403).json({ error: "Invalid email for OTP verification." });

    const entry = otpStore[email];
    if (!entry) return res.status(400).json({ error: "OTP not found. Please request again." });

    if (Date.now() > entry.expiresAt) {
      delete otpStore[email];
      return res.status(400).json({ error: "OTP expired. Please request a new one." });
    }

    if (String(otp).trim() === String(entry.code)) {
      delete otpStore[email]; // one-time use
      return res.json({ message: "OTP verified successfully!" });
    }

    return res.status(400).json({ error: "Invalid OTP" });
  } catch (err) {
    console.error("verify-otp error:", err);
    res.status(500).json({ error: "Failed to verify OTP" });
  }
});

//------------------------- CHECK EMAIL AVAILABILITY -----------------------
app.get('/check-email', async (req, res) => {
  const { email } = req.query;
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!regex.test(email)) return res.status(400).json({ error: 'Invalid email format' });

  try {
    const existingUser = await User.findOne({ email });
    res.json({ available: !existingUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ------------------- VERIFY 2FA -------------------
app.post('/verify', async (req, res) => {
  const { tempToken, twoFactorPassword } = req.body;
  try {
    const payload = jwt.verify(tempToken, 'temp-secret-key');
    const user = await User.findById(payload.userId);
    const isMatch = await bcrypt.compare(twoFactorPassword, user.twoFactorPassword);
    if (!isMatch) return res.status(401).json({ error: 'Incorrect 2FA' });

    const token = jwt.sign({ userId: user._id }, 'final-secret-key', { expiresIn: '1h' });
    res.json({ token });
  } catch {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
});

// ------------------- FILE UPLOAD -------------------
app.post('/upload', auth, upload.single('file'), async (req, res) => {
  const userDir = path.join(__dirname, 'uploads', req.userId);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

  const originalData = fs.readFileSync(req.file.path);
  const encryptedData = encryptBuffer(originalData);

  const finalPath = path.join(userDir, req.file.originalname);
  fs.writeFileSync(finalPath, encryptedData);
  fs.unlinkSync(req.file.path);

  // DB me save
  await File.create({
    userId: req.userId,
    filename: req.file.originalname,
    size: req.file.size,
  });

  res.json({ message: 'File uploaded' });
});


// ------------------- LISTS FILES -------------------
app.get('/files', auth, async (req, res) => {
  const files = await File.find({ userId: req.userId });
  res.json({ files });
});


// ------------------- DOWNLOAD FILES -------------------
app.get('/download/:filename', auth, (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.userId, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });

  const encrypted = fs.readFileSync(filePath);
  const decrypted = decryptBuffer(encrypted);

  res.setHeader('Content-Disposition', `attachment; filename="${req.params.filename}"`);
  res.send(decrypted);
});

// ----------------------- View file (decrypted) --------------------
app.get('/view/:filename', auth, async (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.userId, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });

  try {
    const encrypted = fs.readFileSync(filePath);
    const decrypted = decryptBuffer(encrypted);

    // Increase views count
    await File.findOneAndUpdate(
      { userId: req.userId, filename: req.params.filename },
      { $inc: { views: 1 } }
    );

    const ext = path.extname(req.params.filename).toLowerCase();
    let contentType = 'application/octet-stream';
    if (ext === '.pdf') contentType = 'application/pdf';
    else if (ext === '.png') contentType = 'image/png';
    else if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
    else if (ext === '.txt') contentType = 'text/plain';

    res.setHeader('Content-Type', contentType);
    res.send(decrypted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to decrypt file" });
  }
});

// ----------------------- Delete file ------------------
app.delete('/delete/:filename', auth, async (req, res) => {
  try {
    const file = await File.findOneAndDelete({
      userId: req.userId,
      filename: req.params.filename
    });

    if (!file) return res.status(404).json({ error: 'File not found' });

    // Disk se bhi delete karna
    const filePath = path.join(__dirname, 'uploads', req.userId, req.params.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});


// Serve frontend
app.use(express.static(path.join(__dirname, 'frontend')));

app.get('/', (req, res) => 
  res.sendFile(path.join(__dirname, 'frontend', 'login.html'))
);

app.get('/register', (req, res) => 
  res.sendFile(path.join(__dirname, 'frontend', 'register.html'))
);

app.get('/dashboard', (req, res) => 
  res.sendFile(path.join(__dirname, 'frontend', 'upload.html'))
);


// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});












