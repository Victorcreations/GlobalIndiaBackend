import crypto from "crypto";

function genotp()
{
    return crypto.randomInt(100000,999999).toString();
}

export default genotp;