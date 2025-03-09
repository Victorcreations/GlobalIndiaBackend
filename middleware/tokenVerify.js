import jwt from "jsonwebtoken";
import { credDec } from "./passwordSec.js";
import cookieParser from "cookie-parser";

export const routeVerify = async (req,res,next) => {

    const token = req.cookies.token;

    // try
    // {
    //     token = req.cookies.token;
    // }

    // catch(e)
    // {
    //     console.log("Token error in tokenVerify.js => " + e);
    //     res.status(401).json({ error : "Cannot retrieve token" });
    // }
    

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