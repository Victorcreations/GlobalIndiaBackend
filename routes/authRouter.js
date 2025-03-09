import express from "express";
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import iplogger from "../middleware/connectionlog.js";
import genotp from "../middleware/randomOTP.js";
import sendMail from "../middleware/mailer.js";
import { check, validationResult } from "express-validator";
import { checkUserAvailability, checkUser } from "../middleware/userCheck.js";
import { 
        OTPmodel,
        userModel, 
        dataModel,
        MaterialInquiryModel,
        testModel,
        SupplierModel,
        customerModel
    } from "../config/Schema.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import moment from "moment";
import clearOTP from "../middleware/passwordClear.js";
import { credEnc, credDec } from "../middleware/passwordSec.js";
import { authUser, routeVerify } from "../middleware/tokenVerify.js";

const authRouter = express.Router();

authRouter.use(bodyParser.json());
authRouter.use(bodyParser.urlencoded({ extended: true }));

authRouter.post("/sendotp", async (req, res) => {

        clearOTP();

            const OTP = genotp();

            try {
                const hash = crypto.randomBytes(32).toString('hex');

                const OTPsave = new OTPmodel({ otp: OTP, proof: hash });
                await OTPsave.save();
                req.session.secret = hash;

                try
                {
                    sendMail(OTP, "gokulworkid@gmail.com");
                    res.status(200).json({ mssg : `OTP has been sent to admin` });
                }
                catch(err)
                {
                    console.log(err);
                } 
            }
            catch (e) {
                console.log("OTP error => " + e);
            }
    })

authRouter.post("/registerUser", async (req, res) => {

    const OTP = req.body.otp;

    if (!req.session.secret) {
        console.log("No session found");
        res.status(401).json({ error: "Not authorized" })
    }

    else {
        const secret = req.session.secret;
        const salt = parseInt(process.env.SALT);

        const userName = req.body.name;
        const passwd = req.body.password;
        const mail = req.body.email;
        const role = req.body.role;

        const db_otp = await OTPmodel.findOne({ proof: secret });

        if (db_otp.otp === OTP) {
            const passwdHash = await bcrypt.hash(passwd, salt);
            const new_user = new userModel({ userName: userName, password: passwdHash, Email: mail, role : role })
            await new_user.save();
            res.status(200).json({ mssg: "Success" });
        }

        else
        {
            res.status(403).json({error : "OTP mismatch"})
        }
    }

    clearOTP();
})

authRouter.post("/login", async (req, res) => {

    const Email = req.body.email;
    const passwd = req.body.password;

    const result = await checkUser(Email, passwd);

    const verification = result.map(r => r.msg ? true : false);

    const creds = await userModel.findOne({ Email : Email });

    if (verification.includes(true)) {
        
        try
        {
            const token = jwt.sign(
                    {Email},
                    process.env.TOKEN,
                    {expiresIn : '24h'}                
            )

            res.cookie("token",token,{
                maxAge : 1000 * 60 * 60 * 24 
            })

            res.status(200).json({
                mssg : "Logged in successfully",
                displayName : creds.userName,
                displayMail : creds.Email,
                role : creds.role,
                isAuthenticated : true
            })

        }

        catch(err)
        {
            res.status(500).json({"error" : err});
        }
    }

    else {
        const mssg = result.map(r => r.error);

        res.status(403).json({ error: mssg });
    }

})

authRouter.post("/userAuth", async (req, res) => {

    const receivedOTP = req.body.logOTP;

    const sessionHash = req.session.userVerify;

    if (!sessionHash) {
        res.status(401).json({ error: "User not authorized" });
    }

    else {
        const otp = await OTPmodel.findOne({ proof: sessionHash });

        const current_time = moment();

        const otp_time = moment(otp.createAt);

        const difference = current_time.diff(otp_time, "minutes");

        if (otp.otp === receivedOTP && difference < 2) {
            req.session.dataUserActual = req.session.dataUser;

            res.status(200).json({ mssg: "User authorized" });
        }

        else {
            res.status(401).json({ error: "OTP mismatch or time exceeded" });
        }
    }

});

authRouter.post("/subData",
    [
        check("ordno").notEmpty().withMessage("Order number is an required field"),
        check("material").notEmpty().withMessage("The material field cannot be left empty")
    ]
    , async (req, res) => {

        const order_no = req.body.ordno;
        const material = req.body.material;

        const user = req.session.dataUserActual;

        const userData = await credDec(user);

        const userId = await userModel.findOne({ userName: userData });

        const product = new dataModel(
            {
                ordNo: order_no,
                product: material
            }
        )
    })

authRouter.post("/test", async (req, res) => {
    console.log("Nothing");
})

authRouter.post("/material-inquiry/add-material", async (req, res) => {

    const material = req.body[0].supplierMaterial;
    const order_number = req.body[0].supplementOrderNumber;
    const status = req.body[0].status;
    const explaination = req.body[0].explanation;
    const createTime = req.body[0].createTime;
    const updateTime = req.body[0].updateTime; 
    const user = req.body[1].user

    try
    {
        const MaterialInquiryData = new MaterialInquiryModel(
            {
                Suppliermaterial : material,
                OrderNumber: order_number,
                status: status,
                explaination: explaination,
                createdTime: createTime,
                updateTime: updateTime,
                user : user
            }
        )
    
        await MaterialInquiryData.save();

        res.status(200).json({"mssg" : "Success"})
    }
    catch(err)
    {
        console.log(err);
        res.status(500).json({"error" : err});
    } 
})

authRouter.post("/material-inquiry/get-data",async(req,res) => {

    try
    {
        const user = req.body.email;
        const data = await MaterialInquiryModel.find({user : user});

        res.status(200).json({"data" : data});
    }

    catch(err)
    {
        res.status(500).json({error : err});
    }
})

authRouter.post("/supplier/add-material",async(req,res) =>{

    const customerNumber = req.body[0].customerNumber;
    const customer = req.body[0].customer;
    const status = req.body[0].status;
    const documentStatus = req.body[0].documentStatus;
    const abnormalInfo = req.body[0].abnormalInfo;
    const invite = req.body[0].invitee;
    const reAuthPerson = req.body[0].reAuthPerson;
    const contactInfo = req.body[0].contactInfo;
    const invitationDate = req.body[0].invitationDate;
    const SecondOrderClassification = req.body[0].secondOrderClassification;
    const buyer = req.body[0].buyer;
    const user = req.body[1].user;

    try
    {
        const newData = new SupplierModel(
            {
                customerNumber : customerNumber,
                Customer : customer,
                Status : status,
                DocumentStatus : documentStatus,
                AbnormalInfo : abnormalInfo,
                Invite : invite,
                ReAuthPerson : reAuthPerson,
                ContactInfo : contactInfo,
                InvitationDate : invitationDate,
                SecondOrderClassification : SecondOrderClassification,
                buyer : buyer,
                user : user
            }
        )

        await newData.save();

        res.status(200).json({mssg : "Data saved successfully"})
    }
    catch(err)
    {
        console.log(err);
        res.status(500).json({error : err})
    }
})

authRouter.post("/suppliers/get-data",async(req,res) => {

    try
    {
        const user = req.body.email;
        const data = await SupplierModel.find({user : user});

        res.status(200).json({"data" : data});
    }

    catch(err)
    {
        res.status(500).json({error : err});
    }
})

authRouter.post("/customer/add-data",async(req,res) => {
    
 
    const id = req.body.id;
    const customer = req.body.customer;
    const platformNo = req.body.platformNo;
    const poNo = req.body.poNo;
    const purchaseDate = req.body.purchaseDate;
    const orderAmount = req.body.orderAmount;
    const currency = req.body.currency;
    const purchasingDepartment = req.body.purchasingDepartment;
    const purchaser = req.body.purchaser;
    const requisitionBusinessGroup = req.body.requisitionBusinessGroup
    const deliveryStatus = req.body.deliveryStatus;
    const orderStatus = req.body.orderStatus;
    const acceptanceStatus = req.body.acceptanceStatus;
    const statementStatus = req.body.statementStatus;
    const user = req.body.userName;

    try
    {
        const userData = new customerModel(
            {
                id: id,
                customer: customer,
                platformNo: platformNo,
                poNo: poNo,
                purchaseDate: purchaseDate,
                orderAmount: orderAmount,
                currency: currency,
                purchasingDepartment: purchasingDepartment,
                purchaser: purchaser,
                requisitionBusinessGroup: requisitionBusinessGroup,
                deliveryStatus: deliveryStatus,
                orderStatus: orderStatus,
                acceptanceStatus : acceptanceStatus,
                statementStatus: statementStatus,
                user : user
            }
        )

        await userData.save();

        res.status(200).json({"message" : "Data saved successfully"});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }
})

authRouter.post("/customer/get-data",async(req,res) => {

    const user = req.body.username;
    
    try
    {
        const data = await customerModel.find({user : user});

        res.status(200).json(data);
    }
    catch(err)
    {
        res.status(500).json({"Error" : "There was some problem in fetching the data"});
    }
})


authRouter.post("/test/createData", async(req,res) => {
    const name = req.body.name;
    const password = req.body.password;

    try
    {
        const data = new testModel(
            {
                name:name,
                password:password
            }
        )
    
        const response = await data.save();

        res.status(200).json({"mssg":"Success"});
    }

    catch(e)
    {
        res.status(500).json({"error" : e});
    }
})

authRouter.get("/test/getData",async (req,res) => {

    try
    {
        const data = await testModel.find({},{_id:0,__v:0});

        res.status(200).json(data);
    }

    catch(e)
    {
        res.status(500).json({"error" : "Unable to get data"});
    }
})

authRouter.post("/test/registerUser", async(req,res) => {
    const name = req.body.name;
    const password = req.body.password;
    const mail = req.body.mail;

    try{
        const newUser = new userModel(
            {
                userName : name,
                password : password,
                Email : mail
            }
        )

        await newUser.save();

        return res.status(200).json({"mssg" : "Success"})
    }
    catch(err)
    {
        return res.status(402).json({"error" : err});
    }
})

authRouter.post("/test/login",async(req,res) => {
    const name = req.body.name;
    const password = req.body.password;

    const userData = await userModel.findOne({ userName : name });

    if(!userData)
    {
        res.status(400).json({"error" : "No User found"})
    }

    if(userData.password != password)
    {
        res.status(403).json({"error" : "Password not match"})
    }
    else
    {
        const token = jwt.sign(
            {name},
            process.env.TOKEN,
            {
                expiresIn:'1m'
            }
        )

        res.cookie(
            "token",
            token,
            {
                sameSite: 'Strict',
                maxAge: 1000 * 60
            }
        )
        
        res.status(200).json({"mssg" : "User logged in"});
    }
})

authRouter.post("/test/isAuth",async(req,res) => {
    const token = req.cookies.token;

    try
    {
        const checkToken = jwt.verify(token,process.env.TOKEN);

        if(checkToken)
        {
            res.status(200).json({"message" : "Token valid"});
        }
        else
        {
            res.status(403).json({"message" : "Token invalid"});
        }
    }
    catch(err)
    {
        res.status(403).json({"error" : err});
    }
}) 

export default authRouter;