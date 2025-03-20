import express from "express";
import mongoose, { Mongoose } from "mongoose";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import session from "express-session";
import path from "path";
import clearOTP from "./middleware/passwordClear.js";
import { credEnc,credDec } from "./middleware/passwordSec.js";
import { routeVerify,authUser } from "./middleware/tokenVerify.js";
import authRouter from "./routes/authRouter.js";
import MongoStore from "connect-mongo";
import cors from "cors";

dotenv.config();
const app = express();
const __dirname = path.resolve(); // Get the current directory
app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");
app.set("views","./views");
app.use(express.json());

const allowedOrigins = [
    "http://localhost:3000",
    "http://192.168.29.21:3000"
]
app.use(cookieParser(process.env.SECRET));
app.use(express.static(path.join(__dirname, 'global-react/build'),{
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        } else if (filePath.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css');
        }
    }
}
));

app.use(session(
    {
        secret:process.env.SECRET,
        resave:false,
        saveUninitialized:true,
        store : MongoStore.create(
            {
                mongoUrl : process.env.SESSION_URL
            }
        ),
        cookie : {
            maxAge:1000*60*60*60
        }
    }
))
app.use(cors({
    origin : allowedOrigins,
    credentials : true
}));


mongoose.connect(process.env.DB_URL)
.then(
    app.listen(process.env.PORT,async () => {
        console.log(`Listening on http://localhost:${process.env.PORT}`)
    })
)
.catch(e => {console.log(e)});

app.use("/api",authRouter)