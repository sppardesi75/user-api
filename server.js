require('dotenv').config();
const express = require('express');
const cors = require('cors'); 
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const bodyParser = require('body-parser');

const app = express();
app.use(cors()); 
app.use(bodyParser.json());

// Env variables
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;
if (!MONGO_URL || !JWT_SECRET) {
  console.error("Error: Missing MONGO_URL or JWT_SECRET in .env file.");
  process.exit(1);
}

// DB connection
let db;
MongoClient.connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    db = client.db();
    console.log("Connected to MongoDB");
  })
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// JWT Setup
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET
};

passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
  const usersCollection = db.collection('users');
  usersCollection.findOne({ _id: ObjectId(jwt_payload._id) })
    .then(user => user ? done(null, user) : done(null, false))
    .catch(err => done(err, false));
}));

app.use(passport.initialize());

function checkUser(userName, password) {
  return db.collection('users').findOne({ userName, password }).then(user => {
    if (user) return user;
    throw "Invalid credentials";
  });
}

app.post('/api/user/login', (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) return res.status(400).json({ error: "Missing userName or password" });

  checkUser(userName, password)
    .then(user => {
      const payload = { _id: user._id, userName: user.userName };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
      res.json({ message: "User authenticated", token });
    })
    .catch(() => res.status(401).json({ error: "Invalid credentials" }));
});

app.post('/api/user/register', (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) return res.status(400).json({ error: "Missing userName or password" });

  const usersCollection = db.collection('users');
  usersCollection.findOne({ userName }).then(user => {
    if (user) return res.status(400).json({ error: "User already exists" });

    usersCollection.insertOne({
      userName,
      password,
      favourites: [],
      history: []
    }).then(result => res.json({ message: "User registered", userId: result.insertedId }));
  }).catch(err => res.status(500).json({ error: "Database error" }));
});

// Favourites
app.get('/api/user/favourites', passport.authenticate('jwt', { session: false }), (req, res) => {
  db.collection('users').findOne({ _id: req.user._id })
    .then(user => user ? res.json({ favourites: user.favourites || [] }) : res.status(404).json({ error: "User not found" }))
    .catch(() => res.status(500).json({ error: "Database error" }));
});

app.put('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  db.collection('users').updateOne(
    { _id: req.user._id },
    { $addToSet: { favourites: req.params.id } }
  ).then(() => res.json({ message: "Favourite added" }))
    .catch(() => res.status(500).json({ error: "Database error" }));
});

app.delete('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  db.collection('users').updateOne(
    { _id: req.user._id },
    { $pull: { favourites: req.params.id } }
  ).then(() => res.json({ message: "Favourite removed" }))
    .catch(() => res.status(500).json({ error: "Database error" }));
});

// History
app.get('/api/user/history', passport.authenticate('jwt', { session: false }), (req, res) => {
  db.collection('users').findOne({ _id: req.user._id })
    .then(user => user ? res.json({ history: user.history || [] }) : res.status(404).json({ error: "User not found" }))
    .catch(() => res.status(500).json({ error: "Database error" }));
});

app.put('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  db.collection('users').updateOne(
    { _id: req.user._id },
    { $addToSet: { history: req.params.id } }
  ).then(() => res.json({ message: "History updated" }))
    .catch(() => res.status(500).json({ error: "Database error" }));
});

app.delete('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  db.collection('users').updateOne(
    { _id: req.user._id },
    { $pull: { history: req.params.id } }
  ).then(() => res.json({ message: "History item removed" }))
    .catch(() => res.status(500).json({ error: "Database error" }));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`User API listening on port ${port}`));
