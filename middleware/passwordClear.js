import { OTPmodel } from "../config/Schema.js";
import moment from "moment";

async function clearOTP()
{
    const del_difference = 5;
    const current_time = moment();

    try
    {
        const otp = await OTPmodel.find();
        const exp_otp = otp.map(dates => current_time.diff(dates.createAt,"minutes") > del_difference);

        if(exp_otp.length > 0)
        {
            await OTPmodel.deleteMany({_id : {$in : exp_otp.map(d => d._id)}})
        }
    }

    catch(e)
    {
        return e;
    }
}

export default clearOTP;