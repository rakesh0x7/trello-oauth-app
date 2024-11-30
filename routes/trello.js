const express = require("express");
const OAuth = require("oauth").OAuth;
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const url = require("url");
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET; // Set in your `.env` file
const USERS_FILE = path.join(__dirname, "../data/users.json");

// Trello OAuth Configuration
const requestURL = "https://trello.com/1/OAuthGetRequestToken";
const accessURL = "https://trello.com/1/OAuthGetAccessToken";
const authorizeURL = "https://trello.com/1/OAuthAuthorizeToken";
const appName = "Trello OAuth Example";
const scope = "read,account";
const expiration = "1hour";
const key = "860d8acca66b15ecb972c95c2210d8f9";
const secret = "aa895690079228f9316bd53f78631a0a5ce7bc0e4aee9bc473202836ff32f28a";
const loginCallback = `https://trello-oauth-app.onrender.com/callback`; // Replace with your actual callback URL

const oauth_secrets = {};
const oauth = new OAuth(
  requestURL,
  accessURL,
  key,
  secret,
  "1.0A",
  loginCallback,
  "HMAC-SHA1"
);

// Utility functions for managing users
const readUsers = () => JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
const writeUsers = (users) => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

// Route to initiate login with Trello
router.get("/login", (req, res) => {
  oauth.getOAuthRequestToken((error, token, tokenSecret) => {
    if (error) {
      console.error("Error getting request token:", error);
      res.status(500).send("Failed to initiate login with Trello");
    } else {
      oauth_secrets[token] = tokenSecret;
      const authURL = `${authorizeURL}?oauth_token=${token}&name=${appName}&scope=${scope}&expiration=${expiration}`;
      res.redirect(authURL);
    }
  });
});

// Callback route for Trello OAuth
router.get("/callback", (req, res) => {
  const query = url.parse(req.url, true).query;
  const token = query.oauth_token;
  const verifier = query.oauth_verifier;

  const tokenSecret = oauth_secrets[token];
  if (!tokenSecret) {
    return res.status(400).send("Invalid OAuth flow");
  }

  oauth.getOAuthAccessToken(token, tokenSecret, verifier, (error, accessToken, accessTokenSecret) => {
    if (error) {
      console.error("Error getting access token:", error);
      res.status(500).send("Authentication failed");
    } else {
      oauth.getProtectedResource(
        "https://api.trello.com/1/members/me",
        "GET",
        accessToken,
        accessTokenSecret,
        (error, data) => {
          if (error) {
            console.error("Error accessing Trello API:", error);
            res.status(500).send("Failed to fetch user data");
          } else {
            const userData = JSON.parse(data);
            const email = userData.email;
            const name = userData.fullName;
            
            if (!email) {
              return res.status(500).send("Unable to fetch user email");
            }

            // Check if user exists
            let users = readUsers();
            let user = users.find((u) => u.email === email);
            // console.log("user exits ----------------------------------------------------")
            // console.log(user)

            if (!user) {
              // Register new user
              const newUser = {
                id: users.length + 1,
                email,
                name: name || "New User",
              };
              users.push(newUser);
              writeUsers(users);
              user = newUser;
            }
            // Create JWT token
            const token = jwt.sign(
              { id: user.id, email: user.email, name: user.name },
              JWT_SECRET,
              { expiresIn: "1h" }
            );

            // Store token in localStorage and redirect to profile
            res.send(
              `<html><script>
                window.localStorage.setItem('token', '${token}');
                window.location.href = 'profile.html';
              </script></html>`
            );
          }
        }
      );
    }
  });
});

module.exports = router;
