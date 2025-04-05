require('dotenv').config();
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(cors());
app.options('*', cors());
app.use(express.json());

const userService = require('./user-service');

// Connect to Mongoose (user-service)
userService.connect()
  .then(() => console.log("✅ Connected to user-service (Mongoose)"))
  .catch((err) => {
    console.error("❌ Failed to connect user-service:", err);
    process.exit(1);
  });

// JWT Setup
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET
};

passport.use(new JwtStrategy(opts, async (jwt_payload, done) => {
  try {
    const user = await userService.checkUser({ userName: jwt_payload.userName });
    return user ? done(null, user) : done(null, false);
  } catch (err) {
    return done(err, false);
  }
}));

app.use(passport.initialize());

// Login
app.post('/api/user/login', async (req, res) => {
  try {
    const user = await userService.checkUser(req.body);
    const payload = { _id: user._id, userName: user.userName };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: "User authenticated", token });
  } catch (err) {
    res.status(401).json({ error: err });
  }
});

// Register
app.post('/api/user/register', async (req, res) => {
  try {
    const result = await userService.registerUser(req.body);
    res.json({ message: result });
  } catch (err) {
    res.status(400).json({ error: err });
  }
});

// Favourites
app.get('/api/user/favourites', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const favs = await userService.getFavourites(req.user._id);
    res.json(favs);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.put('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const favs = await userService.addFavourite(req.user._id, req.params.id);
    res.json(favs);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.delete('/api/user/favourites/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const favs = await userService.removeFavourite(req.user._id, req.params.id);
    res.json(favs);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// History
app.get('/api/user/history', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const history = await userService.getHistory(req.user._id);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.put('/api/user/history/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const history = await userService.addHistory(req.user._id, req.params.id);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

app.delete('/api/user/history/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
  try {
    const history = await userService.removeHistory(req.user._id, req.params.id);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`✅ User API listening on port ${port}`));
