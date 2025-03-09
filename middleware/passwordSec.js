import crypto from "crypto";
import { credsModel } from "../config/Schema.js";

async function getKey(){

    try
    {
        const creds = await credsModel.findOne({},{key:1,iv:1,_id:0});

        const keyBuff = Buffer.alloc(32);
        const ivBuff = Buffer.alloc(16);

        Buffer.from(creds.key).copy(keyBuff);
        Buffer.from(creds.iv).copy(ivBuff);

        return { key:keyBuff, iv:ivBuff };
    }
    catch(e)
    {
        console.log(e);
    }
}

const algo = 'aes-256-cbc';

export async function credEnc(text)
{
    const { key, iv } = await getKey();
    const cipher = crypto.createCipheriv(algo,key,iv);
    const encrypted = cipher.update(text,'utf-8','hex') + cipher.final('hex');
    return encrypted;
}

export async function credDec(text)
{
    const { key,iv } = await getKey();
    const decipher = crypto.createDecipheriv(algo,key,iv);
    const decrypted = decipher.update(text,'hex','utf-8') + decipher.final('utf-8');
    return decrypted;
}