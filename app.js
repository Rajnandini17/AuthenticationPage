require('dotenv').config(); // loading environment variables from .env file
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const pg = require("pg");
const bcrypt = require("bcrypt");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

const db = new pg.Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
  });
  db.connect();

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});


//registering a new user with password encryption
app.post("/register", async function(req, res) {
    const email = req.body.username;
    const password = req.body.password;

    try{
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


//validating user login with password encryption
app.post("/login", async function(req, res) {
    const username = req.body.username;
    const enteredPassword = req.body.password;

    try {
        const result = await db.query(
            "SELECT * FROM users WHERE email = $1", 
        [username]
        );
        const foundUser = result.rows[0];
        if (foundUser) {
            const passwordMatch = await bcrypt.compare(enteredPassword, foundUser.password)

            if(passwordMatch) {
                console.log("Login Successful!");
                res.render("secrets");
            } else {
                console.log("Invalid Password!");
                res.redirect("/login");
            }

        } else {
            console.log("User Not Found!");
            res.redirect("/");
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error: " + err.message);
    }
});


app.listen(3000, function(req, res) {
    console.log("Server started on port 3000.");
});
