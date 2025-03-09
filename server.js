import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import session from "express-session";
import path from "path";
import clearOTP from "./middleware/passwordClear.js";
import { credEnc,credDec } from "./middleware/passwordSec.js";
import { routeVerify } from "./middleware/tokenVerify.js";
import authRouter from "./routes/authRouter.js";

dotenv.config();
const app = express();
const __dirname = path.resolve(); // Get the current directory
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");
app.set("views","./views");
app.use(cookieParser(process.env.SECRET));

app.use(session(
    {
        secret:process.env.SECRET,
        resave:false,
        saveUninitialized:true,

        cookie : {
            maxAge:1000*60*60*60
        }
    }
))


mongoose.connect(process.env.DB_URL)
.then(
    app.listen(process.env.PORT,async () => {
        console.log(`Listening on port ${process.env.PORT}`)
    })
)
.catch(e => {console.log(e)});

app.get("/index",(req,res) => {
    res.render("index");
})

app.get("/login",routeVerify,(req,res) => {
    res.render("login");
})

app.use("/api",authRouter)