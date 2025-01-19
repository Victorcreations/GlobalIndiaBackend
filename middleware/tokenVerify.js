import jwt from "jsonwebtoken";
import { credDec } from "./passwordSec.js";
import cookieParser from "cookie-parser";

export const routeVerify = async (req,res,next) => {

    const token = req.cookies.token;
    
    if(!token)
    {
        res.status(401).json({ error : "No token found" })
    }

    else
    {
        try
        {
            const auth = jwt.verify(token,process.env.TOKEN);
            next();
        }
    
        catch(e)
        {
            res.status(401).json({ error : e.message })
        }
    }
} 

export const authUser = async(req,res,next) => {

    const userCreds = req.session.dataUserActual;

    if(!userCreds)
    {
        res.status(401).json({ error : "User is not authorized" });
    }

    else
    {
        next();
    }
}