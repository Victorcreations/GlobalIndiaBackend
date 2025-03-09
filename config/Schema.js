import mongoose from "mongoose";
import { v4 as uuidv4 } from "uuid";

const OTPschema = new mongoose.Schema(
    {
        otp : { type:String,required:true },
        createAt : { type:Date,default:Date.now },
        proof : { type:String,required:true },
        pubId : { type:String,default:uuidv4 }
    }
)

const userSchema = new mongoose.Schema(
    {
        userName : { type:String,required:true },
        password : { type:String,required:true },
        Email : { type:String,required:true,unique:true },
        pubId: { type:String,default:uuidv4 }
    }
)

const credsSchema = new mongoose.Schema(
    {
        key : { type:String },
        iv : { type:String }
    }
)

export const OTPmodel = mongoose.model("OTP",OTPschema,"OTP");
export const userModel = mongoose.model("Users",userSchema,"Users");
export const credsModel = mongoose.model("creds",credsSchema,"creds");