import crypto from "crypto";

function genotp()
{
    return crypto.randomInt(1000,9999).toString();
}

export default genotp;