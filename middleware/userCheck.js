import { userModel } from "../config/Schema.js";
import bcrypt from "bcrypt";

export async function checkUserAvailability(userName,Email)
{
    var result = [0,0];

    try
    {
        const user = await userModel.findOne({userName:userName});
        const mail = await userModel.findOne({Email:Email});
        
        if(user)
        {
            result[0] = 1;
        }

        if(mail)
        {
            result[1] = 1;
        }
    }

    catch(e)
    {
        console.log(e);
    }

    return result;
}

export async function checkUser(userName,Password)
{
    const result = [];

    try
    {
        const user = await userModel.findOne({ userName:userName });
        
        if(!user)
        {
            result[0] = 
            {
                error: "No user found"
            };
        }

        else
        {
            const isValidPasswd = await bcrypt.compare(Password,user.password);
            result[0] = isValidPasswd ? { msg : "Success user match" } : { error : "Password does not match" };
        }
    }

    catch(e)
    {
        console.log("In catch")
        result[0] = { error : "Some error in checking the user" };
    }

    return result;
}