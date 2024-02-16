import 'dotenv/config';
import express, { query } from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";


const app = express();
const port = process.env.SERVER_PORT;
const saltRounds = 10;


app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PWD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", async (req, res) => {
  await db.query("CREATE TABLE users(id SERIAL PRIMARY KEY,name VARCHAR(100),phone VARCHAR(100) NOT NULL UNIQUE,password VARCHAR(100),userid VARCHAR(100) );");
  await db.query("CREATE TABLE orders(id SERIAL PRIMARY KEY,userid VARCHAR(100),subtotal numeric ,phone VARCHAR(100))");
  res.render("home.ejs");

});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/orders", async (req, res) => {
  console.log("in /order,get req",req.user);

  
  if (req.isAuthenticated()) {
    try {
      console.log("in ger orders", req.user);
      const result = await db.query(
        `SELECT * FROM orders WHERE phone = $1`,
        [req.user.phone]
      );
      console.log(result.rows);
      
      if (result.rows.length!==0) {
        res.render("orders.ejs", { list: result.rows });
      } else {
        res.render("orders.ejs", { empty: "No orders yet." });
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/home2", async (req, res) => {
  console.log("in app.get home2",req.user);

  
  if (req.isAuthenticated()) {
    try {
      
      res.render("home2.ejs");
      
        
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});


app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});


app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/home2",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const phone = req.body.username;
  const password = req.body.password;
  const name=req.body.name;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE phone = $1", [
      phone,
    ]);

    if (checkResult.rows.length > 0) {

      res.redirect("/register");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (name, phone, password) VALUES ($1, $2, $3) RETURNING *",
            [name, phone,hash]
          );
          const user = result.rows[0];
          console.log("here",user);
          req.login(user, (err) => {
            if(err)
            {
              console.log(err);
            }
            console.log("success");
            res.redirect("/home2");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});


app.post("/submit", async function (req, res) {
  const submitteduserId = req.body.userid;
  const submittedsubtotal = req.body.subtotal;
  console.log(req.user);
  
  try {
    const result=await db.query(`SELECT * FROM users WHERE phone = $1 `, [
      req.user.phone,
    ]);
    console.log(result.rows);
    if(result.rows[0].userid!==null)
    {
          if (result.rows[0].userid===submitteduserId) {
              try{
              await db.query("INSERT INTO orders (userid, subtotal, phone) VALUES ($1, $2, $3) RETURNING *",
              [submitteduserId, submittedsubtotal, req.user.phone]
            );
            await db.query("UPDATE users SET userid = $1 WHERE phone = $2 ",
            [submitteduserId, req.user.phone]
            );

            }
            catch(err)
            {
              console.log("in post,submit inserting into table orders", err);
            }
          }
          else
          {
              res.redirect("/submit");
          }
          
    }
    else{
      try{
        await db.query("INSERT INTO orders (userid, subtotal, phone) VALUES ($1, $2, $3) RETURNING *",
        [submitteduserId, submittedsubtotal, req.user.phone]
      );
      await db.query("UPDATE users SET userid = $1 WHERE phone = $2 ",
      [submitteduserId, req.user.phone]
      );
      }
      catch(err)
      {
        console.log("in post,submit inserting into table orders", err);
      }
    }
    
    res.redirect("/home2");
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE phone = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        //console.log("in login stragey",user,username,password);
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              
              return cb(null, user);
            } else {
              //console.log("here");
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
