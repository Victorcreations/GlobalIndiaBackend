import bcrypt from "bcrypt";
import { userModel } from "../config/Schema.js";

const password = "password"

async function updatePassword(password) 
{
    const passwd = await bcrypt.hash(password,10);

    return passwd;
}

export async function enc()
{
    try
    {
        const usr = await userModel.find();

        await Promise.all
        (
            usr.map( async(user) => {
                const hash =  updatePassword(user.password);

                await userModel.updateOne( { _id:user._id },{ $set : { password : hash } } )
            } )
        )
    }

    catch(e)
    {
        return { error : e };
    }
}