require('dotenv').config();
require('pg'); // explicitly require the "pg" module
const Sequelize = require('sequelize');
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const bodyParser = require('body-parser');
app.set('views', __dirname + '/views');


const app = express();
app.use(cors());
app.options('*', cors()); // Handle preflight OPTIONS requests
app.use(bodyParser.json());
app.use(express.static(__dirname + '/public'));
// Env variables
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;
if (!MONGO_URL || !JWT_SECRET) {
  console.error("Error: Missing MONGO_URL or JWT_SECRET in .env file.");
  process.exit(1);
}

// Global DB variable
let db;

// Helper function to ensure DB connection is established
async function connectToDatabase() {
  if (!db) {
    try {
      const client = await MongoClient.connect(MONGO_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      });
      db = client.db(); // Use the default database from your connection string
      console.log("Connected to MongoDB");
    } catch (err) {
      console.error("MongoDB connection error:", err);
      throw err;
    }
  }
  return db;
}

// JWT Setup
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET
};

passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
  try {
    const database = await connectToDatabase();
    const usersCollection = database.collection('users');
    const user = await usersCollection.findOne({ _id: ObjectId(jwt_payload._id) });
    return user ? done(null, user) : done(null, false);
  } catch (err) {
    return done(err, false);
  }
}));

app.use(passport.initialize());

// Helper: Check user credentials
function checkUser(userName, password) {
  return connectToDatabase().then(database => {
    return database.collection('users').findOne({ userName, password }).then(user => {
      if (user) return user;
      throw "Invalid credentials";
    });
  });
}

// Login
app.post('/api/user/login', async (req, res) => {
  try {
    const { userName, password } = req.body;
    if (!userName || !password)
      return res.status(400).json({ error: "Missing userName or password" });

    const user = await checkUser(userName, password);
    const payload = { _id: user._id, userName: user.userName };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: "User authenticated", token });
  } catch (err) {
    res.status(401).json({ error: "Invalid credentials" });
  }
});

// Register
app.post('/api/user/register', async (req, res) => {
  try {
    const { userName, password } = req.body;
    if (!userName || !password)
      return res.status(400).json({ error: "Missing userName or password" });

    const database = await connectToDatabase();
    const usersCollection = database.collection('users');
    const existingUser = await usersCollection.findOne({ userName });
    if (existingUser)
      return res.status(400).json({ error: "User already exists" });

    const result = await usersCollection.insertOne({
      userName,
      password, // Note: Hash in production!
      favourites: [],
      history: []
    });
    res.json({ message: "User registered", userId: result.insertedId });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

// Favourites
app.get('/api/user/favourites', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const database = await connectToDatabase();
    const user = await database.collection('users').findOne({ _id: req.user._id });
    if (user) res.json({ favourites: user.favourites || [] });
    else res.status(404).json({ error: "User not found" });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

app.put('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const database = await connectToDatabase();
    await database.collection('users').updateOne(
      { _id: req.user._id },
      { $addToSet: { favourites: req.params.id } }
    );
    res.json({ message: "Favourite added" });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

app.delete('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const database = await connectToDatabase();
    await database.collection('users').updateOne(
      { _id: req.user._id },
      { $pull: { favourites: req.params.id } }
    );
    res.json({ message: "Favourite removed" });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

// History
app.get('/api/user/history', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const database = await connectToDatabase();
    const user = await database.collection('users').findOne({ _id: req.user._id });
    if (user) res.json({ history: user.history || [] });
    else res.status(404).json({ error: "User not found" });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

app.put('/api/user/history/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const database = await connectToDatabase();
    await database.collection('users').updateOne(
      { _id: req.user._id },
      { $addToSet: { history: req.params.id } }
    );
    res.json({ message: "History updated" });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

app.delete('/api/user/history/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const database = await connectToDatabase();
    await database.collection('users').updateOne(
      { _id: req.user._id },
      { $pull: { history: req.params.id } }
    );
    res.json({ message: "History item removed" });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`User API listening on port ${port}`));
