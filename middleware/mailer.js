import nodemailer from "nodemailer";

async function sendMail(data,mailId)
{
    var status;

    const transport = nodemailer.createTransport
    (
        {
            host:process.env.HOST,
            service:process.env.SERVICE,
            secure:true,
            port:process.env.MAIL_PORT,

            auth : {
                user:process.env.MAIL,
                pass:process.env.PASSWORD
            }
        }
    )

    const information = {
        from:process.env.MAIL,
        to:mailId,
        subject:'TEST MAIL',
        text:data
    }

    try
    {
        await transport.sendMail(information,(err,mail) => {

            if(err)
            {
                status = err;
                console.log("Mailer error  => " + err);
            }
                
        })
    }

    catch(e)
    {
        status = e;
        console.log(e);
    }

    return status;
}

export default sendMail;