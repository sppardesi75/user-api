const express = require('express');
const app = express();
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const passportJWT = require("passport-jwt");
const userService = require("./user-service.js");

dotenv.config();

const HTTP_PORT = process.env.PORT || 8080;

// Passport JWT strategy setup
const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
};

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {
  userService.getUserById(jwt_payload._id)
    .then(user => {
      if (user) return done(null, user);
      else return done(null, false);
    })
    .catch(err => done(err, false));
}));

app.use(express.json());
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      "http://localhost:3000",
      "http://192.168.2.24:3000",
      "https://your-frontend.vercel.app" // replace with your deployed frontend
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS not allowed"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));
app.use(passport.initialize());

// Routes

app.post("/api/user/register", (req, res) => {
  userService.registerUser(req.body)
    .then((msg) => res.json({ "message": msg }))
    .catch((msg) => res.status(422).json({ "message": msg }));
});

app.post("/api/user/login", (req, res) => {
  userService.checkUser(req.body)
    .then((user) => {
      const payload = {
        _id: user._id,
        userName: user.userName
      };
      const token = jwt.sign(payload, process.env.JWT_SECRET);
      res.json({ message: "login successful", token });
    })
    .catch(msg => res.status(422).json({ message: msg }));
});

app.get("/api/user/favourites",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService.getFavourites(req.user.userName)
      .then(data => res.json(data))
      .catch(msg => res.status(422).json({ error: msg }));
  });

app.put("/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService.addFavourite(req.user.userName, req.params.id)
      .then(data => res.json(data))
      .catch(msg => res.status(422).json({ error: msg }));
  });

app.delete("/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService.removeFavourite(req.user.userName, req.params.id)
      .then(data => res.json(data))
      .catch(msg => res.status(422).json({ error: msg }));
  });

app.get("/api/user/history",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService.getHistory(req.user.userName)
      .then(data => res.json(data))
      .catch(msg => res.status(422).json({ error: msg }));
  });

app.put("/api/user/history/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService.addHistory(req.user.userName, req.params.id)
      .then(data => res.json(data))
      .catch(msg => res.status(422).json({ error: msg }));
  });

app.delete("/api/user/history/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService.removeHistory(req.user.userName, req.params.id)
      .then(data => res.json(data))
      .catch(msg => res.status(422).json({ error: msg }));
  });

userService.connect()
  .then(() => {
    app.listen(HTTP_PORT, () => {
      console.log("API listening on: " + HTTP_PORT);
    });
  })
  .catch((err) => {
    console.log("unable to start the server: " + err);
    process.exit();
  });
