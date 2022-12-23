//jshint esversion:6

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
//const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();


//initalize express
app.use(express.static("public"));
//initialize ejs
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
//initializing express-session
app.use(session({
  secret: "Our little secret",
  resave: false,
  saveUninitialized: true,
  cookie: {}
}));

//initializing passport
app.use(passport.initialize());
app.use(passport.session());


//mongoose database
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});


//created object of mongose schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//enabling the passportLocalMongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//database encryption
//secret key moved to .env file
// to encrypt the database (ALWAYS ADD BEFORE MONGOOSE MODEL)
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"] });
//THE ABOVE LINE ENCYPTS THE WHOLE DATABASE BUT WE ONLY WANT TO
//ENCRYPT ONLY THE PASSWORD FIELD


//mongoose model
const User = new mongoose.model("User", userSchema);

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(function(user, done){
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
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
});

app.route("/auth/google")
  .get(passport.authenticate('google', {scope: ['profile']}));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
    });

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  //now visible to all logged in or // NOT
  //FINDING ALL THE SECRETS THAT DOES NOT HAVE NULL VALUE IN DATABASE TO DISPLAYI IT
  User.find({"secret": {$ne: null}}, function(err, foundUsers) {
    if(err) {
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });








//if logged in then only we can view this page
  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // } else {
  //   res.redirect("/login");
  // }
});

app.get("/submit", function(req, res) {
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

//GETS THE SECRET ENTERED BY THE USER AND STORES IT IN DATABASE
app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

//WHEN THE USER SUBMITS THEN ITS ID IS ALSO STORED IN THE 'req' HENCE WE CAN ACCESS IT AND CHECK WITH THE DATABASE AND ADD IT
  console.log(req.user.id);
  User.findById(req.user.id, function(err, foundUser) {
    if(err) {
      console.log(err);
    } else {
      if(foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function(req, res) {
  req.logout(function(err) {
    if(!err) {
      res.redirect("/");
    } else {
      console.log(err);
    }
  });

});

//TAKES EMAIL AND PASSWORD TO REGISTER IT AND SAVE IT TO OUR DATABASE
app.post("/register", function(req, res) {

    //THIS DOES THE WORK OF TAKING NEW EMAIL AND PASSWORD FROM USER AND SAVING IT
    User.register({username: req.body.username}, req.body.password, function(err, user) {
      if(err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function(){
          res.redirect("/secrets");
        });
      }
    });







  // //USING BCRYPT TO HASH THE PASSWORD USING saltRounds
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err) {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });
//USING MD5 HASHING PASSOWRD
  // const newUser = new User({
  //   email: req.body.username,
  //   password: md5(req.body.password)
  // });
  // newUser.save(function(err) {
  //   if(err) {
  //     console.log(err);
  //   } else {
  //     res.render("secrets");
  //   }
  // });
});

//ACCEPT EMAIL AND PASSWORD FROM USER AND CHECK FROM DATABASE
app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function(err) {
    if(err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

  //USING BCRYPT HASHING
  // const username = req.body.username;
  // const password = req.body.password;
  // //const password = md5(req.body.password);
  //
  // User.findOne({
  //   email: username
  // }, function(err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       bcrypt.compare(password, foundUser.password, function(err, result) {
  //         if (result === true) {
  //           res.render("secrets");
  //         }
  //       });
  //
  //
  //     }
  //   }
  // });
});

//   User.findOne({email: username}, function(err, foundUser) {
//     if(err) {
//       console.log(err);
//     } else {
//       if(foundUser) {
//         if(foundUser.password === password) {
//           res.render("secrets");
//         }
//       }
//     }
//   });
// });









app.listen(3000, function() {
  console.log("Server started on port 3000");
});
