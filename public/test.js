const sign_up = document.getElementById("sign");

sign_up.addEventListener("click",async () => {

    console.log("clicked");
    try
    {
        const res = await axios.post("http://localhost:8000/api/signup",{
            name : "viper",
            password : "password",
            mail : "viper@gmail.com"
        }
);

        console.log(res.data);
    }

    catch(e)
    {
        console.log(e)
    }
})