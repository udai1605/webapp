require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')

// const encrypt = require("mongoose-encryption");
// const md5=require("md5")      //this is used to encrypt using hashing.
// const saltRounds = 10;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "mysecretcode.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.URL, { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({  //to encrypt the password
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)
// userSchema.plugin(encrypt, {secret:process.env.SECRET,encryptedFields:["password"]}); the encryption method is not that secure

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());                            //this is to create cookie and authenticate user. 
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
       
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render('home');
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get("/login", function (req, res) {
    res.render('login');
});

app.get("/register", function (req, res) {
    res.render('register');
});

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        User.find({"secret":{$ne : null}}, function(err,foundUsers){
            if(err) {
                console.log(err);
            }else{
                if(foundUsers){
                    res.render("secrets",{usersWithSecret : foundUsers})
                }
            }
        });
    } else {
        res.redirect('/login');
    }
   
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render('submit');
    } else {
        res.redirect('/login');
    }
})

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id,function(err,foundUser) {
        if(err) {
            console.log(err);
        }else{
            if(foundUser) {
                foundUser.secret=submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets");
                });
            }
        }
    });
});

app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            res.redirect('/register');
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect('/secrets');
            })
        }
    })
    // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
    //     const newUser =new User({
    //         email:req.body.username,
    //         password: hash                                              //md5(req.body.password) md5 is used for encryption using hashing
    //     });
    //     newUser.save(function(err){
    //         if(err){
    //             console.log(err);
    //         }else{
    //             res.render('secrets');
    //         }
    //     });

    // });

});

app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
})

app.post('/login', function (req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });


    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect('/secrets');
            })
        }
    });
    // const username = req.body.username;
    // const password = req.body.password;                                                      //md5(req.body.password); encrypted using hasing
    // User.findOne({email: username},function(err,foundUser){
    //     if(err){
    //         console.log(err);
    //     }else{

    //         if(foundUser){
    //             bcrypt.compare(password, foundUser.password, function(err,result){
    //                 if(result === true){
    //                     res.render('secrets');
    //                 }else{
    //                     console.log(err);
    //                 }
    //             });

    // if(foundUser.password === password){ //it is a hashing method
    //     res.render('secrets');
    // }
    //         }
    //     }
    // }); 
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port,function(){
    console.log("Server Started");
});