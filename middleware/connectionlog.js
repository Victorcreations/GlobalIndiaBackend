const iplogger = (req,res,next) => {

    console.log(
        "Connected IP => ",req.ip,
        " http version => ",req.httpVersion,
        " host name => ",req.hostname
    );

    next();
}

export default iplogger;