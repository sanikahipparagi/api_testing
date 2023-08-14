const express = require('express')
const router = express.Router();
const config = require("../config/config.js");

const User = require('./../models/User.js');

const bcrypt = require('bcrypt')
const nodemailer = require("nodemailer");
const randomstring = require("randomstring");

const sendResetPasswordMail = async(name,email,token) => {
 try {
   const transporter =  nodemailer.createTransport({
        host:'smtp.gmail',
        port:3000,
        secure:false,
        requireTLS:true,
        auth:{
            user:config.emailUser,
            pass:config.emailPassword
        }
    })

    const mailOptions = {
        from:config.emailUser,
        to:email,
        subject:'For reset password'
    }
    transporter.sendMail(mailOptions,function(error,info){
        if(error){
            console.log(error);
        }
        else{
            console.log("Mail has been sent:-",info.response)
        }
    })



 } catch (error) {
    res.status(400).send({success:false,msg:error.message})
 }
}

router.post('/signup', (req, res) => {
    let{name, email, password} = req.body;
    name = name.trim();
    email = email.trim();
    password = password.trim();

    if(name=="" || email=="" || password==""){
        res.json({
            status: "FAILED",
            message:"Please fill all the fields"
        });
    }else if (password.length < 8) {
        res.json ({
            status : 'FAILED' ,
            message :"Password must be atleast of length 8 characters"
        })
    
    }else {
        User.find({email}).then(result => {
           if(result.length) {
            res.json({
                status:'FAILED',
                message:"User with the provided email already exists"
            })
           }else{
              const saltRounds = 10;
              bcrypt.hash(password, saltRounds).then(hashedPassword => {
                 const newUser = new User({
                    name,
                    email,
                    password: hashedPassword
                 });

                 newUser.save().then(result => {
                    res.json({
                        status: "SUCCESSFUL",
                        message: "Register Successful",
                        data: result
                    })
                 }).catch(err=>{
                    res.json({
                        status: "FAILED",
                        message:"An error occured while saving user account!"
                    })
                })
            })
              
              .catch(err => {
                res.json({
                    status: "FAILED",
                    message:"An error occured while hasing password"
                })
              })
           }
         }).catch(err => {
            console.log(err);
            res.json({
                status:'FAILED',
                message: "An error occurred while checking for existing user!"
            })
        })
    }
})


router.post('/signin',(req, res) => {
    let{name, password} = req.body;
    name = name.trim();
    password = password.trim();

    if(name=="" || password==""){
        res.json({
            status : 'FAILED',
            message :"Please fill all the fields."
        })
    }else {
        //check if user exists in database or not
        User.find({name})
        .then(data => {
            if(data.length) {

                const hashedPassword = data[0].password;
                bcrypt.compare(password, hashedPassword).then(result => {
                    if(result) {

                        res.json({
                            status: 'SUCCESSFUL',
                            message:"Login Successful",
                            data: data
                        })
                    } else {
                        res.json({
                            status: "FAILED",
                            message:"Incorrect Password!!"
                        })
                    }
                })
                .catch(err => {
                    res.json({
                        status: "FAILED",
                        message: "An error occured while comparing the password"
                    })
                    
                })
            }else {
                res.json ({
                    status: "FAILED",
                    message: `User with name does not exist!`
                })
            }
        })
        .catch(err => {
            res.json({
                status: "FAILED",
                message: "An error occurred while checking for existing user"
            })
        })
    }
})

router.post('/forget-password',async (req,res) => {
    try {

        const email = req.body.email;
        const userData = await User.findOne({email:email});
   
        if(userData){
             const randomString = randomstring.generate();
            const data = await User.updateOne({email:email},{$set:{token:randomString}})
            sendResetPasswordMail(userData.name,userData.email,randomString)
            res.status(200).send({success:true,msg:"Please check your inbox of mail and reset your password"})
        }
        else{
           res.status(200).send({success:true,msg:"this email does not exist"});
        }
       } catch (error) {
           res.status(400).send({success:false,msg:error.message})
       }
})

module.exports = router;