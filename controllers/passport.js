// import { Strategy as GoogleStrategy } from "passport-google-oauth20";
// import passport from "passport";
// import path from "path";
// import { fileURLToPath } from "url";
// import dotenv from "dotenv";
// const __dirname = path.dirname(fileURLToPath(import.meta.url));

// dotenv.config({ path: path.join(__dirname, "env") });

// passport.use(
//     new GoogleStrategy(
//         {
//             clientID: process.env.CLIENT_ID,
//             clientSecret: process.env.CLIENT_SECRET,
//             callbackURL: "http://localhost:5000/api/users/google/callback",
//             scope: ["profile", "email"],
//         },
//         function (accessToken, refreshToken, profile, done) {
//             done(null, profile);
//         }
//     )
// );

// passport.serializeUser((user, done) => {
//     done(null, user);
// });

// passport.deserializeUser((user, done) => {
//     done(null, user);
// });