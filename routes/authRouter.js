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
        customerModel,
        customerDeliveryModel,
        materialReplenishmentModel,
        dailyWorkModel
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

                try
                {
                    sendMail(OTP, "gokulworkid@gmail.com");
                    res.status(200).json(
                        { 
                            mssg : `OTP has been sent to admin`,
                            secret : hash 
                        });
                }
                catch(err)
                {
                    console.log(err);
                } 
            }
            catch (e) {
                console.log("OTP error => " + e);
            }
    });

authRouter.post("/check-user",async(req,res) => {

    const email = req.body.email;

    try
    {
        const response = await userModel.findOne({Email : email});

        if(!response)
        {
            res.status(200).json({"Success" : "User not found"});
        }
        else
        {
            res.status(406).json({"error" : "User already exists"});
        }
    }
    catch(err)
    {
        res.status(500).json({"error" : "Internal server error"});
    }
})

authRouter.post("/registerUser", async (req, res) => {

    const OTP = req.body.newUser.otp;
    const secret = req.body.newUser.secret;

    if (!secret || !OTP) {
        res.status(401).json({ error: "Not authorized" })
    }

    else {
        const salt = parseInt(process.env.SALT);

        const userName = req.body.newUser.name;
        const passwd = req.body.newUser.password;
        const mail = req.body.newUser.email;
        const role = req.body.newUser.role;

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

authRouter.post("/super-register",async(req,res) =>{

    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    const role = req.body.role;
    const salt = parseInt(process.env.SALT);

    try
    {
        if(!name || !email || !password || !role){
            return res.status(406).json({"error" : "Data missing"});
        }

        const userExists = await userModel.findOne({Email : email});

        if(userExists){
            return res.status(409).json({"error" : "User already exists"});
        }

        const passwdHash = await bcrypt.hash(password, salt);

        const newUser = new userModel({
            userName : name,
            Email : email,
            password : passwdHash,
            role : role
        })

        await newUser.save();

        res.status(200).json({"success" : "New user created"});
    }
    catch(err)
    {
        res.status(500).json({"error" : "Failed to create user"});
    }
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
                mobile : creds.mobile,
                location : creds.location,
                bio : creds.info,
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

authRouter.post("/get-clients",async(req,res) => {

    try
    {
        const users = await userModel.find({role : "client"});

        res.status(200).json({"users" : users});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
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

authRouter.get("/material-inquiry/get-all",async(req,res) => {
    try
    {
        const data = await MaterialInquiryModel.find();

        res.status(200).json({"data" : data});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
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

authRouter.get("/suppliers/get-all",async(req,res) => {
    
    try
    {
        const data = await SupplierModel.find();

        res.status(200).json({"data" : data});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }
})

authRouter.post("/customer/add-data",async(req,res) => {

    const customer = req.body[0].customer;
    const platformNo = req.body[0].platformNo;
    const poNo = req.body[0].poNo;
    const purchaseDate = req.body[0].purchaseDate;
    const orderAmount = req.body[0].orderAmount;
    const currency = req.body[0].currency;
    const purchasingDepartment = req.body[0].purchasingDepartment;
    const purchaser = req.body[0].purchaser;
    const requisitionBusinessGroup = req.body[0].requisitionBusinessGroup
    const deliveryStatus = req.body[0].deliveryStatus;
    const orderStatus = req.body[0].orderStatus;
    const acceptanceStatus = req.body[0].acceptanceStatus;
    const statementStatus = req.body[0].statementStatus;
    const user = req.body[1].user;

    try
    {
        const userData = new customerModel(
            {
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

    const user = req.body.email;
    
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

authRouter.get("/customer/get-all",async(req,res) => {
    try{
        const data = await customerModel.find();

        res.status(200).json({"data" : data});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }
})

authRouter.post("/customerdelivery/add-data",async(req,res) => {
    
    const orderNumber = req.body[0].orderNumber;
    const materialCategory = req.body[0].materialCategory;
    const vendor = req.body[0].vendor;
    const invitee = req.body[0].invitee;
    const hostInviterContactInfo = req.body[0].hostInviterContactInfo;
    const sender = req.body[0].sender;
    const status = req.body[0].status;
    const supplementTemplate = req.body[0].supplementTemplate;
    const isMonitored = req.body[0].isMonitored;
    const user = req.body[1].user;

    try
    {
        const newData = new customerDeliveryModel(
            {
                user:user,
                OrderNumber : orderNumber,
                MaterialCategory : materialCategory,
                Vendor : vendor,
                Invitee : invitee,
                Host : hostInviterContactInfo,
                Sender : sender,
                Status : status,
                SupplementTemplate : supplementTemplate,
                Actions : isMonitored
            }
        )

        await newData.save();

        res.status(200).json({"mssg" : "data saved"});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }
})

authRouter.post("/customerdelivery/get-data",async(req,res) => {

    const user = req.body.email;
    
    try
    {
        const data = await customerDeliveryModel.find({user : user});

        res.status(200).json(data);
    }
    catch(err)
    {
        res.status(500).json({"Error" : "There was some problem in fetching the data"});
    }
})

authRouter.get("/customerdelivery/get-all",async(req,res) => {
    try{
        const data = await customerDeliveryModel.find();

        res.status(200).json({"data" : data});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }
})

authRouter.post("/edit-user",async(req,res) => {

    const email = req.body.data.email;
    const name = req.body.data.fullName;
    const mobile = req.body.data.mobile;
    const location = req.body.data.location;
    const bio = req.body.data.bio;

    try
    {
        const userExists = await userModel.findOne({Email : req.body.data.email});

        if(userExists)
        {
            await userModel.updateOne({Email : email},
                {
                    $set : {
                        userName : name,
                        mobile : mobile,
                        location : location,
                        info : bio
                    }
                }
            )

            res.status(200).json({"success" : "Data updated"});
        }
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }


})

authRouter.post("/material-replenishment/add-data",async(req,res) => {

    const orderNumber = req.body[0].orderNumber;
    const materialCategory = req.body[0].materialCategory;
    const vendor = req.body[0].vendor;
    const invitee = req.body[0].invitee;
    const hostInviterContactInfo = req.body[0].hostInviterContactInfo;
    const sender = req.body[0].sender;
    const status = req.body[0].status;
    const supplementTemplate = req.body[0].supplementTemplate;
    const createTime = req.body[0].createTime;
    const updateTime = req.body[0].updateTime;
    const user = req.body[1].user;

    try
    {
        const data = new materialReplenishmentModel(
            {
                user:user,
                OrderNumber : orderNumber,
                MaterialCategory : materialCategory,
                Vendor : vendor,
                Invitee : invitee,
                Host : hostInviterContactInfo,
                Sender : sender,
                Status : status,
                SupplementTemplate : supplementTemplate,
                Created : createTime,
                updated : updateTime
            }
        )

        await data.save();

        res.status(200).json({"message" : "Data saved"});
    }
    catch(err)
    {
        console.log(err);
        res.status(500).json({"error" : err});
    }
})

authRouter.post("/material-replenishment/get-data",async(req,res) => {

    const user = req.body.email;
    
    try
    {
        const data = await materialReplenishmentModel.find({user : user});

        res.status(200).json(data);
    }
    catch(err)
    {
        res.status(500).json({"Error" : "There was some problem in fetching the data"});
    }
})

authRouter.get("/material-replenishment/get-all",async(req,res) => {
    try{
        const data = await materialReplenishmentModel.find();

        res.status(200).json({"data" : data});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }
})

authRouter.post("/dailywork/add-data",async(req,res) => {

    console.log(req.body);
    const companyName = req.body[0].companyName;
    const projectName = req.body[0].projectName;
    const superVisorName = req.body[0].supervisorName;
    const managerName = req.body[0].managerName;
    const prepaidBy = req.body[0].prepaidBy;
    const employees = req.body[0].employees;
    const workTypes = req.body[0].workType;
    const progress = req.body[0].progress;
    const hours = req.body[0].hours;
    const charges = req.body[0].charges;
    const date = req.body[0].date;
    const user = req.body[1].user;

    try
    {
        const data = new dailyWorkModel(
            {
                user : user,
                CompanyName : companyName,
                ProjectName : projectName,
                SupervisorName : superVisorName,
                ManagerName : managerName,
                PrepaidBy : prepaidBy,
                Employee : employees,
                NatureofWork : workTypes,
                Progress : progress,
                HourofWork : hours,
                Charges : charges,
                Date : date
            }
        )

        await data.save();

        res.status(200).json({"message" : "Data saved successfully"});
    }
    catch(err)
    {
        console.log(err);
        res.status(500).json({"error" : err})
    }
})

authRouter.post("/dailywork/get-data",async(req,res) => {

    const user = req.body.email;
    
    try
    {
        const data = await dailyWorkModel.find({user : user});

        res.status(200).json(data);
    }
    catch(err)
    {
        res.status(500).json({"Error" : "There was some problem in fetching the data"});
    }
})

authRouter.get("/dailywork/get-all",async(req,res) => {
    try{
        const data = await dailyWorkModel.find();

        res.status(200).json({"data" : data});
    }
    catch(err)
    {
        res.status(500).json({"error" : err});
    }
})

export default authRouter;