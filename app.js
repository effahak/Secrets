//jshint esversion:6
import "dotenv/config";
import bcrypt from "bcrypt";
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import pkg from "pg";
const { Pool } = pkg;

const db = new Pool({
  user: "postgres",
  host: "localhost",
  database: "world",
  password: process.env.DB_PASSWORD,
  port: "5432",
});

const port = 3000;
const app = express();
const saltRounds = 10;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

async function addUser(name, pass) {
  const hashedPassword = await bcrypt.hash(pass, saltRounds);
  const result = await db.query(
    "insert into au_user(email,password) values($1,$2)",
    [name, hashedPassword]
  );
  return result;
}

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  try {
    await addUser(req.body.username, req.body.password);
    res.render("secrets");
  } catch (err) {
    console.error(err);
  }
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const passKey = req.body.password;

  try {
    const result = await db.query(
      "select password from au_user where email = $1",
      [username]
    );

    const isMatch = await bcrypt.compare(passKey, result.rows[0].password);
    if (isMatch) {
      res.render("secrets");
    } else {
      console.log("wrong password ");
      res.redirect("/login");
    }
  } catch (err) {
    console.error("Username does not exist");
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  res.redirect("/");
});

app.get("/submit", (req, res) => {
  res.render("submit");
});

app.post("/submit", async (req, res) => {
  try {
    const secret = req.body.secret;
    console.log(secret);
    if (secret) {
      await db.query("Insert into secrets(secret) values($1)", [secret]);
      res.render("secrets");
    } else {
      throw new Error("Invalid Input");
    }
  } catch (err) {
    res.render("submit", { error: err });
    console.log(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}!`);
});

// a@a.a passkey a@a.a
