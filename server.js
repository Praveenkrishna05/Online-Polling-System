const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = (process.env.JWT_SECRET || '').trim();
const MONGO_URI = (process.env.MONGO_URI || '').trim();

if (!JWT_SECRET) {
  console.error('JWT_SECRET is missing. Set it in your .env file.');
  process.exit(1);
}

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
});
const User = mongoose.model('User', userSchema);

const pollSchema = new mongoose.Schema({
  question: { type: String, required: true, trim: true },
  options: [{ text: String, votes: { type: Number, default: 0 } }],
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  votedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', default: [] }]
});
const Poll = mongoose.model('Poll', pollSchema, 'polls');

const logSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Log = mongoose.model('Log', logSchema);

const isDbReady = () => mongoose.connection.readyState === 1;

const requireDb = (req, res, next) => {
  if (!isDbReady()) {
    return res.status(503).json({
      error: 'Database unavailable. Check MONGO_URI/network and retry.'
    });
  }
  next();
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

const isUser = (req, res, next) => {
  if (req.user.role !== 'user') {
    return res.status(403).json({ error: 'Only users can perform this action' });
  }
  next();
};

const createDefaultAdminIfConfigured = async () => {
  const username = (process.env.ADMIN_USERNAME || '').trim();
  const password = (process.env.ADMIN_PASSWORD || '').trim();

  if (!username || !password) return;

  const existing = await User.findOne({ username });
  if (existing) return;

  const hashed = await bcrypt.hash(password, 10);
  await User.create({ username, password: hashed, role: 'admin' });
  console.log(`Default admin created: ${username}`);
};

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    dbConnected: isDbReady(),
    timestamp: new Date().toISOString()
  });
});

app.post('/api/register', requireDb, async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: 'Username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashedPassword, role: 'user' });

    await Log.create({ userId: user._id, action: 'User registered' });
    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', requireDb, async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id.toString(), username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    await Log.create({ userId: user._id, action: 'User logged in' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/logout', requireDb, authenticateToken, async (req, res) => {
  try {
    await Log.create({ userId: req.user.id, action: 'User logged out' });
    res.json({ message: 'Logout recorded' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/polls', requireDb, authenticateToken, isAdmin, async (req, res) => {
  const question = (req.body.question || '').trim();
  const options = Array.isArray(req.body.options)
    ? req.body.options.map(opt => String(opt || '').trim()).filter(Boolean)
    : [];

  if (!question || options.length < 2) {
    return res.status(400).json({ error: 'Question and at least two options required' });
  }

  try {
    const poll = await Poll.create({
      question,
      options: options.map(text => ({ text, votes: 0 })),
      createdBy: req.user.id
    });

    await Log.create({ userId: req.user.id, action: `Created poll: ${poll.question}` });
    res.status(201).json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/polls', requireDb, async (req, res) => {
  try {
    const polls = await Poll.find().populate('createdBy', 'username').sort({ createdAt: -1 });
    res.json(polls);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/polls/:id/vote', requireDb, authenticateToken, isUser, async (req, res) => {
  const optionIndex = Number(req.body.optionIndex);

  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll || Number.isNaN(optionIndex) || optionIndex < 0 || optionIndex >= poll.options.length) {
      return res.status(400).json({ error: 'Invalid poll or option' });
    }

    const alreadyVoted = poll.votedBy.some(voterId => voterId.toString() === req.user.id);
    if (alreadyVoted) {
      return res.status(403).json({ error: 'You have already voted on this poll' });
    }

    poll.options[optionIndex].votes += 1;
    poll.votedBy.push(req.user.id);
    await poll.save();

    await Log.create({ userId: req.user.id, action: `Voted on poll: ${poll.question}` });
    res.json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/polls/:id/like', requireDb, authenticateToken, async (req, res) => {
  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(404).json({ error: 'Poll not found' });

    poll.likes += 1;
    await poll.save();

    await Log.create({ userId: req.user.id, action: `Liked poll: ${poll.question}` });
    res.json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/polls/:id', requireDb, authenticateToken, isAdmin, async (req, res) => {
  const question = (req.body.question || '').trim();
  const options = Array.isArray(req.body.options)
    ? req.body.options.map(opt => String(opt || '').trim()).filter(Boolean)
    : [];

  if (!question || options.length < 2) {
    return res.status(400).json({ error: 'Question and at least two options required' });
  }

  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(404).json({ error: 'Poll not found' });

    poll.question = question;
    poll.options = options.map(text => ({
      text,
      votes: poll.options.find(opt => opt.text === text)?.votes || 0
    }));

    await poll.save();
    await Log.create({ userId: req.user.id, action: `Edited poll: ${poll.question}` });
    res.json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/polls/:id', requireDb, authenticateToken, isAdmin, async (req, res) => {
  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(404).json({ error: 'Poll not found' });

    await poll.deleteOne();
    await Log.create({ userId: req.user.id, action: `Deleted poll: ${poll.question}` });
    res.json({ message: 'Poll deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/logs', requireDb, authenticateToken, isAdmin, async (req, res) => {
  try {
    const logs = await Log.find().populate('userId', 'username').sort({ timestamp: -1 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/vote-analysis', requireDb, authenticateToken, isAdmin, async (req, res) => {
  try {
    const polls = await Poll.find();
    const analysis = polls.map(poll => ({
      question: poll.question,
      totalVotes: poll.options.reduce((sum, opt) => sum + opt.votes, 0),
      likes: poll.likes,
      options: poll.options.map(opt => ({ text: opt.text, votes: opt.votes }))
    }));

    res.json(analysis);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const connectToDatabase = async () => {
  if (!MONGO_URI) {
    console.error('MONGO_URI is missing. Set it in your .env file.');
    return;
  }

  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
    console.log('Connected to MongoDB');
    await createDefaultAdminIfConfigured();
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    console.error('API will return 503 until DB connection is available.');
  }
};

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
connectToDatabase();
