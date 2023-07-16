
require('dotenv').config();
const bcrypt = require('bcrypt');
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate = require('mongoose-findorcreate');
const PORT = process.env.PORT || 3003;
 
const app = express();
 
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
 
app.use(session({
    secret: "My secret for site.",
    resave: false,
    saveUninitialized: false
}));
 
 
passport.serializeUser(function (user, done) {
    done(null, user.id);
});
 
passport.deserializeUser(async function (id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});
 
 
 
app.use(passport.initialize());
app.use(passport.session());
 
 
mongoose.connect("mongodb+srv://Shubhayu:Z3Z5AbNay2yPcyqa@cluster0.8mywdid.mongodb.net/UserDB", { useNewUrlParser: true });
 
 
const userSchema = new Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String,
    username: { type: String, unique: false, sparse: true }
});
 
 
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
 
 
const User = mongoose.model("User", userSchema);
 
 
passport.use(User.createStrategy());
userSchema.plugin(findOrCreate);
 
 
passport.use(new GoogleStrategy({
    clientID:"205986069692-cgo99dhfpjoudp5v2fge83hahshabl2h.apps.googleusercontent.com",
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3003/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
 
}, async function (accessToken, refreshToken, profile, cb) {
    try {
        // Deleting indexes before searching or creating a user
        await User.collection.dropIndexes();
        console.log('Indexes have been successfully deleted');
 
        User.findOrCreate({ username: profile.displayName, googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    } catch (error) {
        console.log('Error deleting indexes:', error);
    }
}));
 
 

 
 
app.get('/', function (req, res) {
    res.render("home");
 
});
 
 
app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));
 
 
app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });
 
 

 
app.route("/login")
    .get(function (req, res) {
        res.render("login");
    })
    .post(async function (req, res) {
        const user = new User({ username: req.body.username, password: req.body.password });
 
        req.login(user, function (err) {
            try {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                });
            } catch (error) {
                console.log(err);
            }
        });
    });
 
 
app.route("/register")
    .get(function (req, res) {
        res.render("register");
    })
    .post(async function (req, res) {
        try {
            const user = new User({ username: req.body.username });
            await User.register(user, req.body.password);
 
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        } catch (err) {
            console.log(err);
            res.send('<script>alert("Failed to register the user."); window.location.href = "/login";</script>');
            res.render("register");
        }
    });
 
 
app.get("/secrets", async function (req, res) {
    try {
        const foundUsers = await User.find({ "secret": { $ne: null } });
        res.render("secrets", { usersWithSecrets: foundUsers });
    } catch (error) {
        console.log(err);
    }
});
 
 
app.route("/submit")
    .get(function (req, res) {
        try {
            if (req.isAuthenticated()) {
                res.render("submit");
            } else {
                res.redirect("/login");
            }
        }
        catch (err) {
            res.send('<script>alert("Failed to login."); window.location.href = "/login";</script>');
            console.log(err);
        }
    })
    .post(async function (req, res) {
        try {
            if (req.isAuthenticated()) {
                const submittedSecret = req.body.secret;
                console.log(req.user.id);
                const foundUser = await User.findById(req.user.id);
                if (foundUser) {
                    foundUser.secret = submittedSecret;
                    await foundUser.save();
                    res.redirect("/secrets");
                } else {
                    res.send('<script>alert("Who are you? Do we know each other? Please log in."); window.location.href = "/login";</script>');
                    console.log(req.user.id);
                }
            }
        } catch (err) {
            res.send('<script>alert("Failed to login."); window.location.href = "/login";</script>');
            console.log(err);
        }
    });
 
 
app.get("/logout", function (req, res) {
    req.logout(function () {
        res.redirect("/");
    });
});
 
 
 
app.listen(PORT, function () {
    console.log("started on 3003");
 
});
