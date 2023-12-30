// require('dotenv').config(); // loading environment variables from .env file
// const express = require("express");
// const bodyParser = require("body-parser");
// const ejs = require("ejs");
// const pg = require("pg");
// const bcrypt = require("bcrypt");

// const app = express();

// app.use(express.static("public"));
// app.set('view engine', 'ejs');
// app.use(bodyParser.urlencoded({extended: true}));

// const db = new pg.Client({
//     user: process.env.DB_USER,
//     host: process.env.DB_HOST,
//     database: process.env.DB_DATABASE,
//     password: process.env.DB_PASSWORD,
//     port: process.env.DB_PORT,
//   });
//   db.connect();

// app.get("/", function(req, res) {
//     res.render("home");
// });

// app.get("/login", function(req, res) {
//     res.render("login");
// });

// app.get("/register", function(req, res) {
//     res.render("register");
// });


// //registering a new user with password encryption
// app.post("/register", async function(req, res) {
//     const email = req.body.username;
//     const password = req.body.password;

//     try{
//         const hashedPassword = await bcrypt.hash(password, 10);

//         const result = await db.query(
//             "INSERT INTO users (email, password) VALUES ($1, $2)",
//             [email, hashedPassword]
//         );
//         res.render("secrets");
//     } catch (err) {
//         console.error(err);
//         res.status(500).send("Internal Server Error");
//     }  
// });


// //validating user login with password encryption
// app.post("/login", async function(req, res) {
//     const username = req.body.username;
//     const enteredPassword = req.body.password;

//     try {
//         const result = await db.query(
//             "SELECT * FROM users WHERE email = $1", 
//         [username]
//         );
//         const foundUser = result.rows[0];
//         if (foundUser) {
//             const passwordMatch = await bcrypt.compare(enteredPassword, foundUser.password)

//             if(passwordMatch) {
//                 console.log("Login Successful!");
//                 res.render("secrets");
//             } else {
//                 console.log("Invalid Password!");
//                 res.redirect("/login");
//             }

//         } else {
//             console.log("User Not Found!");
//             res.redirect("/");
//         }
//     } catch (err) {
//         console.error(err);
//         res.status(500).send("Internal Server Error: " + err.message);
//     }
// });


// app.listen(3000, function(req, res) {
//     console.log("Server started on port 3000.");
// });


require('dotenv').config(); // loading environment variables from .env file
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const pg = require("pg");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const session = require("express-session");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: "your-secret-key", // Change this to a secure key
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});
db.connect();

// Passport.js configuration
passport.use(new LocalStrategy(
    {
        usernameField: 'username',
        passwordField: 'password'
    },
    async function (username, password, done) {
        try {
            const result = await db.query(
                "SELECT * FROM users WHERE email = $1",
                [username]
            );
            const foundUser = result.rows[0];

            if (foundUser) {
                const passwordMatch = await bcrypt.compare(password, foundUser.password);

                if (passwordMatch) {
                    return done(null, foundUser);
                } else {
                    return done(null, false, { message: 'Invalid Password' });
                }
            } else {
                return done(null, false, { message: 'User Not Found' });
            }
        } catch (err) {
            return done(err);
        }
    }
));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
    try {
        const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
        const user = result.rows[0];
        done(null, user);
    } catch (err) {
        done(err);
    }
});

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

// Registering a new user with password encryption
app.post("/register", async function (req, res) {
    const email = req.body.username;
    const password = req.body.password;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [email, hashedPassword]
        );
        res.render("secrets");
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});

// Authenticating user with Passport.js
app.post("/login",
    passport.authenticate('local', {
        successRedirect: '/secrets',
        failureRedirect: '/login',
        failureFlash: true
    })
);

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", function (req, res) {
    req.logout(function(err){
        if(err) {
            console.error(err);
            return res.status(500).send("Internal Server Error");
        }
        res.redirect("/");
    });
});

app.listen(3000, function (req, res) {
    console.log("Server started on port 3000.");
});
