import express from "express";
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import iplogger from "../middleware/connectionlog.js";
import genotp from "../middleware/randomOTP.js";
import sendMail from "../middleware/mailer.js";
import { check,validationResult } from "express-validator";
import { checkUserAvailability,checkUser } from "../middleware/userCheck.js";
import { OTPmodel,userModel } from "../config/Schema.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import moment from "moment";
import clearOTP from "../middleware/passwordClear.js";
import { credEnc,credDec } from "../middleware/passwordSec.js";
import { routeVerify } from "../middleware/tokenVerify.js";
import { enc } from "../middleware/test.js";

const authRouter = express.Router();

authRouter.use(bodyParser.json());
authRouter.use(bodyParser.urlencoded({extended:true}));

authRouter.post(
    "/signup",
    [
        check('name').notEmpty().withMessage('Name cannot be empty'),
        check('password').notEmpty().withMessage('Password is an required field'),
        check('mail').isEmail().withMessage('Wrong mail format'),
        check('mail').notEmpty().withMessage('Mail is an required field')
    ]
    ,iplogger,async (req,res) => {

    clearOTP();

    const errors = validationResult(req);

    if(!errors.isEmpty())
    {
        res.status(406).json({ error : errors.array().map(err => err.msg) });
    }

    const userName = req.body.name;
    const passwd = req.body.password;
    const mail = req.body.mail;

    const availability = await checkUserAvailability(userName,mail);

    if(availability[0] === 1 && availability[1] === 1)
    {
        res.status(409).json({ error : "Both the username and mail ID exists" })
    }

    else if(availability[1] === 1)
    {
        res.status(409).json({ error : "User with a same mail ID exists" })
    }

    else if(availability[0] === 1)
    {
        res.status(409).json({ error : "Username already exists" })
    }

    else
    {
        const OTP = genotp(); 

        const salt = parseInt(process.env.SALT);

        try
        {
            const hash = crypto.randomBytes(32).toString('hex');

            const OTPsave = new OTPmodel({ otp:OTP,proof:hash });
            await OTPsave.save();
            req.session.secret = hash;

            req.session.user = await credEnc(userName);
            req.session.pass = await credEnc(passwd);
            req.session.mail = await credEnc(mail);

            try
            {
                const token = jwt.sign
                (
                    { userName },
                    process.env.TOKEN,
                    {
                        expiresIn:'1h'
                    }
                )

                res.cookie(
                    "token",
                    token,
                    {
                        httpOnly:true,
                        secure:true,
                        sameSite:'Strict',
                        maxAge:1000*60*60
                    }
                )
            }

            catch(e)
            {
                console.log("Token error in server.js => " + e);
            }
            
            sendMail(OTP,"gokulworkid@gmail.com");
            
            res.status(200).json({ mssg: `OTP has been sent to admin` });
        }

        catch(e)
        {
            console.log("OTP error => "+e);
        }
    }
})

authRouter.post("/registerUser",routeVerify,async (req,res) =>{

    const OTP = req.body.otp;

    if(!req.session.secret)
    {
        res.status(401).json({ error : "Not authorized" })
    }

    else
    {
        const secret = req.session.secret;
        const salt = parseInt(process.env.SALT);

        const userName = await credDec(req.session.user);
        const passwd = await credDec(req.session.pass);
        const mail = await credDec(req.session.mail);

        const db_otp = await OTPmodel.findOne({proof:secret});

        const current_time = moment();

        const otp_time = moment(db_otp.createAt);

        const difference = current_time.diff(otp_time,"minutes");

        if(db_otp.otp === OTP && difference < 2)
        {
            const passwdHash = await bcrypt.hash(passwd,salt);
            const new_user = new userModel({ userName:userName, password:passwdHash, Email:mail })
            await new_user.save();
            res.status(200).json({ mssg : "Success" });
        }
    }

    clearOTP();
})

authRouter.post("/login",async (req,res) => {

    const userName = req.body.name;
    const passwd = req.body.password;

    const result = await checkUser(userName,passwd);

    const verification = result.map(r => r.msg ? true : false);

    if(verification.includes(true))
    {
        const mail = await userModel.findOne( { userName:userName },{ Email:1,_id:0 } );
        
        const otp = genotp();

        const secureHash = crypto.randomBytes(32).toString('hex');

        req.session.userVerify = secureHash;

        const sentOTP = new OTPmodel({otp:otp,proof:secureHash});

        sentOTP.save();

        sendMail(otp,mail.Email);

        res.status(200).json({ mssg : "OTP sent to the registered mail id" });
    }

    else
    {
        const mssg = result.map(r => r.error);

        res.status(401).json({ error : mssg });
    }

})

authRouter.post("/userAuth",async (req,res) => {

    const receivedOTP = req.body.otp;

    const sessionHash = req.session.userVerify;

    if(!sessionHash)
    {
        res.status(401).json({ error:"User not authorized" });
    }

    else
    {
        const otp = await OTPmodel.findOne({proof:sessionHash});

        const current_time = moment();

        const otp_time = moment(otp.createAt);

        const difference = current_time.diff(otp_time,"minutes");

        if(otp.otp === receivedOTP && difference < 2)
        {
            res.status(200).json({ mssg : "User authorized" });
        }
    }
 
});

authRouter.post("/test",async (req,res) => {
    
})

export default authRouter;