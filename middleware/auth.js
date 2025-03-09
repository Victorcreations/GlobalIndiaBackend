import jwt from "jsonwebtoken";

const authReq = async (req,res,next,err) => {
    console.log("Invoked");

    if(err)
    {
        console.log(err);
    }

    else
    {
        
    }

    next();
}

export default authReq;