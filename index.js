import express from "express";
import { connection } from "./db.js";
import bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";
import session from "express-session";
import methodOverride from "method-override";
import path from "path";
import { fileURLToPath } from "url";
import 'dotenv/config'

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ================== MIDDLEWARE ==================
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride("_method"));
app.use(express.static("public"));
app.use(express.static(path.join(__dirname, "public")));

app.use(
    session({
        secret: "your_secret_key",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            maxAge: 1000 * 60 * 60,
        },
    })
);

// ================== AUTH MIDDLEWARE ==================
function isLoggedIn(req, res, next) {
    console.log("Checking authentication for userId:", req.session.userId);
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    next();
}

// ================== ROUTES ==================

// HOME
app.get("/", (req, res) => {
    if (req.session.userId) return res.redirect("/dashboard");
    res.redirect("/login");
});

// LOGIN PAGE
app.get("/login", (req, res) => {
    res.render("login");
});

// LOGIN LOGIC
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const [user] = await connection.query(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );


        if (user.length === 0) {
            return res.status(404).send("User not found");
        }

        const userObj = user[0];
        console.log(userObj);

        const isMatch = await bcrypt.compare(password, userObj.password);
        console.log("Password Match:", isMatch);
        if (!isMatch) {
            return res.status(401).send("Invalid password");
        }

        // session set
        req.session.userId = userObj.userId;
        req.session.username = userObj.username;
        req.session.isLoggedIn = true;

        req.session.save(() => {
            console.log("Session saved, redirecting to dashboard...");
            res.redirect("/dashboard");
            console.log("Redirected to dashboard");
        });

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).send("Something went wrong");
    }
});

// REGISTER PAGE
app.get("/register", (req, res) => {
    res.render("register");
});

// REGISTER LOGIC
app.post("/register", async (req, res) => {
    const { name, email, password, cpassword } = req.body;

    if (password !== cpassword) {
        return res.send("Password and Confirm Password do not match");
    }

    try {
        // ✅ check email exists
        const [existing] = await connection.query(
            "SELECT userId FROM users WHERE email = ?",
            [email]
        );

        if (existing.length > 0) {
            return res.send("Email already registered");
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const userId = uuid();

        await connection.query(
            "INSERT INTO users (userId, username, email, password) VALUES (?, ?, ?, ?)",
            [userId, name, email, hashedPassword]
        );

        req.session.userId = userId;
        req.session.username = name;

        req.session.save(() => {
            res.redirect("/dashboard");
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Register error");
    }
});

// DASHBOARD
app.get("/dashboard", isLoggedIn, async (req, res) => {
    console.log("Accessing dashboard for user:", req.session.username);
    try {

        res.render("dashboard", {
            name: req.session.username,
        });
    } catch (err) {
        console.error(err);
        res.status(500).send("Dashboard error");
    }
});

// LOGOUT
app.get("/logout", isLoggedIn, (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error(err);
            return res.send("Logout error");
        }
        res.redirect("/login");
    });
});

// ADD PASSWORD PAGE
app.get("/add-user", isLoggedIn, (req, res) => {
    res.render("new");
});

// ADD PASSWORD LOGIC
app.post("/add-user", isLoggedIn, async (req, res) => {
    const { website, email, password } = req.body;
    const user_Id = req.session.userId;
    const id = uuid()
    try {
        const q = 'INSERT INTO passwordsInfos (id, websiteUrl, email, password, user_id) VALUES (?, ?, ?, ?, ?)';
        await connection.query(q, [id, website, email, password, user_Id]);
        res.redirect("/dashboard");
    }
    catch (err) {
        console.error(err);
        res.status(500).send("Error adding password");
    }
});

//VIEW ALL PASSWORDS
app.get("/passwords", isLoggedIn, async (req, res) => {
    const user_Id = req.session.userId;
    try {
        const [passwords] = await connection.query(
            "SELECT * FROM passwordsInfos WHERE user_id = ?",
            [user_Id]
        );
        console.log("Retrieved passwords:", passwords);
        res.render("show", { passwords });
    } catch (error) {
        console.error(error);
    }
});

// EDIT PASSWORD PAGE
app.get('/edit/:id', isLoggedIn, async (req, res) => {
    const editId = req.params.id;
    const passwordPost = await connection.query('SELECT * FROM passwordsInfos WHERE id = ?', [editId]);
    console.log("Password to edit:", passwordPost[0][0]);
    res.render('edit', { password: passwordPost[0][0] });
});

// EDIT PASSWORD LOGIC
app.patch('/edit', isLoggedIn, async (req, res) => {
    const { id, website, email, password } = req.body;
    console.log("Updating password with id:", id);

    try {
        const q = 'UPDATE passwordsInfos SET websiteUrl = ?, email = ?, password = ? WHERE id = ?';
        await connection.query(q, [website, email, password, id]);
        res.redirect("/passwords");
    } catch (error) {
        console.error("Error updating password:", error);
        res.status(500).send("Error updating password");
    }
});

app.delete('/delete/:id', isLoggedIn, async (req, res) => {
    const deleteId = req.params.id;
    console.log("Deleting password with id:", deleteId);
    try {
        const q = 'DELETE FROM passwordsInfos WHERE id = ?';
        await connection.query(q, [deleteId]);
        res.redirect("/passwords");
    } catch (error) {
        console.error("Error deleting password:", error);
        res.status(500).send("Error deleting password");
    }
});

app.get("/security", isLoggedIn, (req, res) => {
    res.render("security");
});


// ================== SERVER ==================
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});