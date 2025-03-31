// server.js

require('dotenv').config();
const express = require('express');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// Ensure environment variables are set
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;
if (!MONGO_URL || !JWT_SECRET) {
  console.error("Error: Missing MONGO_URL or JWT_SECRET in .env file.");
  process.exit(1);
}

// Connect to MongoDB
let db;
MongoClient.connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    db = client.db(); // Use the default database from your connection string
    console.log("Connected to MongoDB");
  })
  .catch(err => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// Set up Passport JWT Strategy
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET
};

passport.use(new JwtStrategy(opts, (jwt_payload, done) => {
  // Find the user in the database based on the _id in the payload
  const usersCollection = db.collection('users');
  usersCollection.findOne({ _id: ObjectId(jwt_payload._id) })
    .then(user => {
      if (user) {
        return done(null, user);
      }
      return done(null, false);
    })
    .catch(err => done(err, false));
}));

app.use(passport.initialize());

/**
 * Helper function: checkUser
 * Validates that the provided credentials match a user document.
 * NOTE: In a production app, passwords should be hashed.
 */
function checkUser(userName, password) {
  return new Promise((resolve, reject) => {
    const usersCollection = db.collection('users');
    usersCollection.findOne({ userName: userName, password: password })
      .then(user => {
        if (user) {
          resolve(user);
        } else {
          reject("Invalid credentials");
        }
      })
      .catch(err => reject(err));
  });
}

/**
 * POST /api/user/login
 * Validates a user's credentials. If successful, creates a JWT payload containing
 * _id and userName, signs it, and returns it to the client.
 */
app.post('/api/user/login', (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) {
    return res.status(400).json({ error: "Missing userName or password" });
  }

  checkUser(userName, password)
    .then(user => {
      // Create JWT payload
      const payload = {
        _id: user._id,
        userName: user.userName
      };

      // Sign the payload to generate a token (expires in 1 hour)
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

      res.json({ message: "User authenticated", token: token });
    })
    .catch(err => {
      res.status(401).json({ error: "Invalid credentials" });
    });
});

/**
 * Protected routes (require a valid JWT in the Authorization header as a Bearer token)
 */

// GET /api/user/favourites
app.get('/api/user/favourites', passport.authenticate('jwt', { session: false }), (req, res) => {
  const usersCollection = db.collection('users');
  usersCollection.findOne({ _id: req.user._id })
    .then(user => {
      if (user) {
        res.json({ favourites: user.favourites || [] });
      } else {
        res.status(404).json({ error: "User not found" });
      }
    })
    .catch(err => res.status(500).json({ error: "Database error" }));
});

// PUT /api/user/favourites/:id
app.put('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  // Add a new favourite item (the item's id is passed in the URL)
  const favId = req.params.id;
  const usersCollection = db.collection('users');
  usersCollection.updateOne(
    { _id: req.user._id },
    { $addToSet: { favourites: favId } }
  )
    .then(() => res.json({ message: "Favourite added" }))
    .catch(err => res.status(500).json({ error: "Database error" }));
});

// DELETE /api/user/favourites/:id
app.delete('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  // Remove a favourite item (the item's id is passed in the URL)
  const favId = req.params.id;
  const usersCollection = db.collection('users');
  usersCollection.updateOne(
    { _id: req.user._id },
    { $pull: { favourites: favId } }
  )
    .then(() => res.json({ message: "Favourite removed" }))
    .catch(err => res.status(500).json({ error: "Database error" }));
});

// GET /api/user/history
app.get('/api/user/history', passport.authenticate('jwt', { session: false }), (req, res) => {
  const usersCollection = db.collection('users');
  usersCollection.findOne({ _id: req.user._id })
    .then(user => {
      if (user) {
        res.json({ history: user.history || [] });
      } else {
        res.status(404).json({ error: "User not found" });
      }
    })
    .catch(err => res.status(500).json({ error: "Database error" }));
});

// PUT /api/user/history/:id
app.put('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  // Add an item to the user's history list
  const itemId = req.params.id;
  const usersCollection = db.collection('users');
  usersCollection.updateOne(
    { _id: req.user._id },
    { $addToSet: { history: itemId } }
  )
    .then(() => res.json({ message: "History updated" }))
    .catch(err => res.status(500).json({ error: "Database error" }));
});

// DELETE /api/user/history/:id
app.delete('/api/user/history/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
  // Remove an item from the user's history list
  const itemId = req.params.id;
  const usersCollection = db.collection('users');
  usersCollection.updateOne(
    { _id: req.user._id },
    { $pull: { history: itemId } }
  )
    .then(() => res.json({ message: "History item removed" }))
    .catch(err => res.status(500).json({ error: "Database error" }));
});

/**
 * Optional: User Registration Endpoint
 * Allows new users to register. (In production, ensure to hash passwords.)
 */
app.post('/api/user/register', (req, res) => {
  const { userName, password } = req.body;
  if (!userName || !password) {
    return res.status(400).json({ error: "Missing userName or password" });
  }
  const usersCollection = db.collection('users');

  // Check if the user already exists
  usersCollection.findOne({ userName: userName })
    .then(user => {
      if (user) {
        return res.status(400).json({ error: "User already exists" });
      }
      const newUser = {
        userName,
        password, // Remember: Hash passwords before storing in production
        favourites: [],
        history: []
      };
      usersCollection.insertOne(newUser)
        .then(result => {
          res.json({ message: "User registered", userId: result.insertedId });
        })
        .catch(err => res.status(500).json({ error: "Database error" }));
    })
    .catch(err => res.status(500).json({ error: "Database error" }));
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`User API listening on port ${port}`);
});
