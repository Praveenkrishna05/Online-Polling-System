const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
require('dotenv').config();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Atlas connection
mongoose.connect(process.env.MONGO_URI
)
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('MongoDB Atlas connection error:', err));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET';

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// Poll Schema
const pollSchema = new mongoose.Schema({
  question: { type: String, required: true },
  options: [{ text: String, votes: { type: Number, default: 0 } }],
  createdAt: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  votedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', default: [] }]
});
const Poll = mongoose.model('Poll', pollSchema, 'polls');

// Log Schema
const logSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const Log = mongoose.model('Log', logSchema);

// Middleware
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

const isUser = (req, res, next) => {
  if (req.user.role !== 'user') return res.status(403).json({ error: 'Only users can perform this action' });
  next();
};

// Routes
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    const log = new Log({ userId: user._id, action: 'User registered' });
    await log.save();
    res.status(201).json({ message: 'User registered' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    const log = new Log({ userId: user._id, action: 'User logged in' });
    await log.save();
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    const log = new Log({ userId: req.user.id, action: 'User logged out' });
    await log.save();
    res.json({ message: 'Logout recorded' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/polls', authenticateToken, isAdmin, async (req, res) => {
  const { question, options } = req.body;
  if (!question || !options || options.length < 2) {
    return res.status(400).json({ error: 'Question and at least two options required' });
  }
  try {
    const poll = new Poll({
      question,
      options: options.map(text => ({ text, votes: 0 })),
      createdBy: req.user.id
    });
    await poll.save();
    const log = new Log({ userId: req.user.id, action: `Created poll: ${poll.question}` });
    await log.save();
    res.status(201).json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/polls', async (req, res) => {
  try {
    const polls = await Poll.find().populate('createdBy', 'username');
    res.json(polls);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/polls/:id/vote', authenticateToken, isUser, async (req, res) => {
  const { optionIndex } = req.body;
  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll || optionIndex < 0 || optionIndex >= poll.options.length) {
      return res.status(400).json({ error: 'Invalid poll or option' });
    }
    if (poll.votedBy.includes(req.user.id)) {
      return res.status(403).json({ error: 'You have already voted on this poll' });
    }
    poll.options[optionIndex].votes += 1;
    poll.votedBy.push(req.user.id);
    await poll.save();
    const log = new Log({ userId: req.user.id, action: `Voted on poll: ${poll.question}` });
    await log.save();
    res.json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/polls/:id/like', authenticateToken, async (req, res) => {
  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(400).json({ error: 'Poll not found' });
    poll.likes += 1;
    await poll.save();
    const log = new Log({ userId: req.user.id, action: `Liked poll: ${poll.question}` });
    await log.save();
    res.json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/polls/:id', authenticateToken, isAdmin, async (req, res) => {
  const { question, options } = req.body;
  if (!question || !options || options.length < 2) {
    return res.status(400).json({ error: 'Question and at least two options required' });
  }
  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(404).json({ error: 'Poll not found' });
    poll.question = question;
    poll.options = options.map(text => ({ text, votes: poll.options.find(opt => opt.text === text)?.votes || 0 }));
    await poll.save();
    const log = new Log({ userId: req.user.id, action: `Edited poll: ${poll.question}` });
    await log.save();
    res.json(poll);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/polls/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const poll = await Poll.findById(req.params.id);
    if (!poll) return res.status(404).json({ error: 'Poll not found' });
    await poll.deleteOne();
    const log = new Log({ userId: req.user.id, action: `Deleted poll: ${poll.question}` });
    await log.save();
    res.json({ message: 'Poll deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/logs', authenticateToken, isAdmin, async (req, res) => {
  try {
    const logs = await Log.find().populate('userId', 'username').sort({ timestamp: -1 });
    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/vote-analysis', authenticateToken, isAdmin, async (req, res) => {
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

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
