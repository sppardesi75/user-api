require('dotenv').config();
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const userService = require('./user-service');

const app = express();
app.use(cors());
app.use(express.json());
app.use(passport.initialize());

const JWT_SECRET = process.env.JWT_SECRET;
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET,
};

passport.use(
  new JwtStrategy(jwtOptions, async (jwt_payload, done) => {
    try {
      const user = await userService.checkUser({ userName: jwt_payload.userName, password: "" });
      return user ? done(null, user) : done(null, false);
    } catch (err) {
      return done(null, false);
    }
  })
);

userService.connect()
  .then(() => {
    console.log("Connected to MongoDB.");

    // Register
    app.post("/api/user/register", async (req, res) => {
      try {
        await userService.registerUser(req.body);
        res.json({ message: "User registered successfully" });
      } catch (err) {
        res.status(400).json({ error: err });
      }
    });

    // Login
    app.post("/api/user/login", async (req, res) => {
      try {
        const user = await userService.checkUser(req.body);
        const payload = {
          _id: user._id,
          userName: user.userName,
        };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful", token });
      } catch (err) {
        res.status(401).json({ error: err });
      }
    });

    // Protected Routes
    app.get("/api/user/favourites", passport.authenticate("jwt", { session: false }), async (req, res) => {
      try {
        const data = await userService.getFavourites(req.user._id);
        res.json(data);
      } catch (err) {
        res.status(500).json({ error: err });
      }
    });

    app.put("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
      try {
        const data = await userService.addFavourite(req.user._id, req.params.id);
        res.json(data);
      } catch (err) {
        res.status(500).json({ error: err });
      }
    });

    app.delete("/api/user/favourites/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
      try {
        const data = await userService.removeFavourite(req.user._id, req.params.id);
        res.json(data);
      } catch (err) {
        res.status(500).json({ error: err });
      }
    });

    app.get("/api/user/history", passport.authenticate("jwt", { session: false }), async (req, res) => {
      try {
        const data = await userService.getHistory(req.user._id);
        res.json(data);
      } catch (err) {
        res.status(500).json({ error: err });
      }
    });

    app.put("/api/user/history/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
      try {
        const data = await userService.addHistory(req.user._id, req.params.id);
        res.json(data);
      } catch (err) {
        res.status(500).json({ error: err });
      }
    });

    app.delete("/api/user/history/:id", passport.authenticate("jwt", { session: false }), async (req, res) => {
      try {
        const data = await userService.removeHistory(req.user._id, req.params.id);
        res.json(data);
      } catch (err) {
        res.status(500).json({ error: err });
      }
    });

    const port = process.env.PORT || 8080;
    app.listen(port, () => console.log(`Server running on port ${port}`));
  })
  .catch((err) => {
    console.error("Unable to connect to MongoDB:", err);
  });
