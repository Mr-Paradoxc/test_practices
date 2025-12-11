import express from "express";
import { Pool } from "pg";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const app = express();


const pool = new Pool({
    user: "postgres",
    host: "localhost",
    database: "postgres",
    password: "postgres",
    port: 5432,
});
const port = 3000;
const SECRET_KEY = "my_super_secret_key_shhh"; // The "Stamp" ink

// This line tells the computer to understand the data coming from the form
app.use(express.urlencoded({ extended: true }));
// This line helps us read the cookie (where we keep the stamp)
app.use(cookieParser());

// This line tells express to serve static files from the "public" folder
app.use(express.static("public"));

app.get("/", (req, res) => {
    // We send a simple HTML form to the browser
    res.send(`
        <h1>Sign Up (Create Account)</h1>
        <form action="/submit-data" method="POST">
            <input type="text" name="myname" placeholder="Enter Name" required>
            <br><br>
            <input type="email" name="myemail" placeholder="Enter Email" required>
            <br><br> 
            <input type="password" name="mypassword" placeholder="Enter Password" required>
            <br><br>
            <button type="submit">Create Account</button>
        </form>
        <br>
        <a href="/login">Already have an account? Login here</a>
    `);
});

app.post("/submit-data", async (req, res) => {
    const name = req.body.myname;
    const email = req.body.myemail;
    const password = req.body.mypassword;

    // 1. BLEND THE PASSWORD (Hashing)
    const hashedPassword = await bcrypt.hash(password, 10);

    // 2. Save the BLENDED password, not the real one
    pool.query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3)", [name, email, hashedPassword], (err, dbRes) => {
        if (err) {
            console.log(err);
            res.send("Something went wrong! " + err);
        } else {
            res.send("<h1>Account Created!</h1> <a href='/login'>Go to Login</a>");
        }
    });
});


app.get("/login", (req, res) => {
    res.send(`
        <h1>Login</h1>
        <form action="/login" method="POST">
            <input type="email" name="checkemail" placeholder="Email" required>
            <br><br>
            <input type="password" name="checkpassword" placeholder="Password" required>
            <br><br>
            <button type="submit">Login</button>
            <br><br>
            <a href="/">Go to Sign Up</a>
        </form>
    `);
});

app.post("/login", (req, res) => {
    const email = req.body.checkemail;
    const password = req.body.checkpassword;

    pool.query("SELECT * FROM users WHERE email = $1", [email], async (err, dbRes) => {
        if (err) {
            console.log(err);
            res.send("Error checking database");
        } else {
            if (dbRes.rows.length > 0) {
                const user = dbRes.rows[0];

                // 1. COMPARE THE BLENDER SMOOTHIES
                // Does 'password' (Strawberry) blend into 'user.password' (Pink Smoothie)?
                const match = await bcrypt.compare(password, user.password);

                if (match) {
                    // 2. GIVE THE HAND STAMP (JWT)
                    const token = jwt.sign({ id: user.id, name: user.name }, SECRET_KEY);

                    // Put the stamp in their pocket (Cookie)
                    res.cookie("token", token, { httpOnly: true });

                    res.redirect("/dashboard");
                } else {
                    res.send("<h1>Login Failed</h1> <p>Wrong password.</p> <a href='/login'>Try again</a><br><br><a href='/'>Go to Sign Up</a>");
                }
            } else {
                res.send("<h1>Login Failed</h1> <p>User not found.</p> <a href='/login'>Try again</a><br><br><a href='/'>Go to Sign Up</a>");
            }
        }
    });
});


// THE VIP SECTION (Protected Route)
app.get("/dashboard", (req, res) => {
    // 1. CHECK THE STAMP
    const token = req.cookies.token;

    if (!token) {
        return res.send("<h1>Stop!</h1> <p>You need to login first.</p> <a href='/login'>Login</a>");
    }

    try {
        // 2. VERIFY THE STAMP
        const verified = jwt.verify(token, SECRET_KEY);
        // If code gets here, the stamp is real!

        // Show the secret page
        res.send(`
            <h1>Welcome to the VIP Dashboard, ${verified.name}!</h1> 
            <p>We know it is you because you have the secret stamp.</p>
            <a href="/logout">Logout</a>
        `);
    } catch (err) {
        res.send("<h1>Fake Stamp!</h1> <p>Get out.</p>");
    }
});

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.redirect("/login");
});

app.get("/setup-db", (req, res) => {
    // 1. DELETE the old table (so we can add the password column)
    pool.query("DROP TABLE IF EXISTS users", (err, dbRes) => {
        // 2. CREATE the new table with a password column
        pool.query("CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(100), email VARCHAR(100), password VARCHAR(100))", (err, dbRes) => {
            if (err) {
                console.log(err);
                res.status(500).send(err);
            } else {
                res.send("<h1>Database Reset!</h1> <p>Old users deleted. New table created with Password support.</p> <a href='/'>Go to Sign Up</a>");
            }
        });
    });
});



app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
