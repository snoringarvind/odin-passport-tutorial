const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const path = require("path");
require("dotenv/config");
const bcrypt = require("bcryptjs");
const saltrounds = 10;
//setup connection

const connection = mongoose.createConnection(
  process.env.DB_Connection,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  () => console.log("DB_Connected")
);

const UserModel = connection.model(
  "User",
  new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

//
const app = express();

//set view engine
app.set("view engine", "pug");

//middlewares
app.use(
  session({
    secret: "cats",
    saveUninitialized: false,
    resave: true,
  })
);

//this middleware is called when we call passport.authenticate
passport.use(
  new LocalStrategy((username, password, done) => {
    console.log("username", username, "password=", password);
    UserModel.findOne({ username: username }, async (err, result) => {
      console.log("result=", result);

      if (err) return done(err);
      bcrypt.compare(password, result.password, (bcrypterr, bcryptresult) => {
        if (bcrypterr) return done(err);
        if (result == null) {
          done(null, false, { msg: "result null" });
          return;
        }
        if (!result) {
          done(null, false, { msg: "Incorrect username" });
          return;
        }
        if (bcryptresult == false) {
          done(null, false, { msg: "Incorrect password" });
          return;
        }
        return done(null, result);
      });
    });
  })
);

passport.serializeUser((user, done) => {
  console.log("user=", user);
  done(null, user.id);
});
passport.deserializeUser((id, done) => {
  UserModel.findById(id, (err, result) => {
    done(err, result);
  });
});

app.use(passport.initialize());
app.use(passport.session());

//*body-parser
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

//routes
app.get("/", (req, res) => {
  res.render("index", { title: "Home page", user: req.user });
});

app.get("/sign-up", (req, res) => {
  res.render("sign-up-form", { title: "Sign up form" });
});

app.post("/sign-up", (req, res, next) => {
  bcrypt.hash(req.body.password, saltrounds, (err, hash) => {
    if (err) return next(err);
    const user = new UserModel({
      username: req.body.username,
      password: hash,
    }).save((err) => {
      if (err) return next(err);
      res.redirect("/");
    });
  });
});

app.post(
  "/log-in",
  passport.authenticate("local", { successRedirect: "/", failureRedirect: "/" })
);

app.get("/log-out", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.listen(3000);
