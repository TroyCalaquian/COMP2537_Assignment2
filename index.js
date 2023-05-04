require("./utils.js");

require("dotenv").config();

const express = require("express");
const app = express();

const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");

const port = 3000;

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection("users");

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true&w=majority`,
  crypto: {
    secret: mongodb_session_secret,
  },
  dbName: "sessions",
});

app.use(session({ 
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false, 
  resave: true
}
));

app.get("/", (req,res) => {
  if (req.session.authenticated) {
    res.redirect("/members");
  } else {
    res.render("index");
  }
});

app.get("/signup", (req,res) => {
  res.render("signup");
});

app.get("/login", (req,res) => {
  res.render("login");
});

app.post("/createUser", async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    username: Joi.string().alphanum().max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(30).required(),
  });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    const errorDetails = validationResult.error.details[0];
    /* Change to ejs file */
    switch (errorDetails.context.key) {
      case "username":
        var html = "Please provide a valid username.";
        break;
      case "email":
        var html = "Please provide a valid email.";
        break;
      case "password":
        var html = "Please provide a valid password.";
        break;
      default:
        var html = "Invalid registration information.";
    }
    res.send(html + `<br/><br/><button onclick="location.href='/signup'">Try again</button>`);
  } else {
    var hashedPassword = await bcrypt.hash(password, 10);

    await userCollection.insertOne({username: username, email: email, password: hashedPassword});
    console.log("user created");
    req.session.authenticated = true;
    const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, user_type: 'user', _id:1}).toArray();
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;
  
    res.redirect("/members");
  }
});

app.post('/loginUser', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(30).required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render("loginfail");
    return;
  }

  const result = await userCollection.find({email: email}).project({email: 1, username: 1, password: 1, _id:1}).toArray();

  console.log(result);
  if (result.length != 1) {
    console.log(validationResult.error);
    res.render("loginfail");
    return;
  }

  if (await bcrypt.compare(password, result[0].password)) {
    console.log("login success");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
    return;
  } else {
    res.render("loginfail");
    console.log("login failed");
    return;
  }
});

app.get("/members", (req,res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  } else {
    let username = req.session.username;
    res.render("members", {username: username});
  }
});

app.get("/admin", async (req,res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  } else {
    users = await userCollection.find().toArray();
    res.render("admin", {users: users});
  }
});

/* TODO: Add promote and demote options here */

app.get("/logout", (req,res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 