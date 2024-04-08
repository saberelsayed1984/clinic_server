import passport from 'passport';
import User from '../models/userModel.js';
import httpStatusText from '../utlits/httpStatus.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import genrateJwt from '../utlits/genrateJwt.js';
import nodemailer from "nodemailer";
import Joi from "joi";
import emailValidator from 'email-validator';
import validator from 'validator';
import { token } from 'morgan';
import path from "path";
import multer from "multer";
import cloudinary from 'cloudinary';
import fs from "fs";
import {cloudinaryUploadImage,cloudinaryRemoveImage} from "../utlits/cloudinary.js";
import { error } from 'console';
const __filename = path.basename(import.meta.url);
const __dirname = path.dirname(__filename);
export async function uplodePhoto(req, res) {
    const userId = req.params.id;
    const user = await User.findById(userId);
    if (!user) {
        return res.status(404).json({ msg: "User not found" });
    }

    
    if (!req.file) {
        return res.status(400).json({ msg: "file provided" });
    }

    const imagePath = path.join(__dirname, `./image/${req.file.filename}`);
    const result = await cloudinaryUploadImage(imagePath);

    if (user.profilePhoto && user.profilePhoto.publicId !== null) {
        await cloudinaryRemoveImage(user.profilePhoto.publicId);
    }

    user.profilePhoto = {
        url: result.secure_url,
        publicId: result.public_id,
    };

    await user.save(); // Save the user's changes first

    res.status(200).json({
        error: false,
        msg: "successfully Upload",
        profilePhoto: { url: result.secure_url, publicId: result.public_id },
    });

    fs.unlinkSync(imagePath);
}
export async function register(req, res, next)  {
    const { Name, email, password } = req.body;
    const oldUser = await User.findOne({ email: email });
    
    if (oldUser) {
        return res.status(400).json({ error: "User already exists" });

    }{
    async function isNameValid(Name)
{
    if (validator.isEmpty(Name)) {
        return { valid: false, msg: 'name is require' };
      }
      const length = validator.isLength(Name,3)
      if(!length){
        return { valid: false, msg: 'Name must be greater than 3 character ' };
      }
     else{ return { valid: true };
}} 
let { valid, msg } = await isNameValid(Name);    
        if (!valid) {return res.status(400).send({ msg })};

    }  
     { async function isPasswordValid(password)
    {
        if (validator.isEmpty(password)) {
            return { valid: false, msg: 'password is require' };
          }
          const length = validator.isLength(password,8)
          if(!length){
            return { valid: false, msg: 'password must be greater than 8 character ' };
          }
        
          return { valid: true };
    } 
    let { valid, msg } = await isPasswordValid(password);    
            if (!valid) {return res.status(400).send({ msg })};
    }
    { async function isEmailValid(email) {

        if (validator.isEmpty(email)) {
            return { valid: false, msg: 'email is require' };
          }
        const isValid = emailValidator.validate(email);
        if (!isValid) {
          return { valid: false,msg: 'Invalid email address' };
        }
        const emailParts = email.split('@');
        if (emailParts.length !== 2 || emailParts[1] !== 'gmail.com') {
          return { valid: false, msg: 'Only Gmail addresses are allowed' };
        }
        return { valid: true };
      } 
      const { valid, msg } = await isEmailValid(email);    
    if (!valid) {return res.status(400).send({msg })};
    }
    

    // password hashing by bcrypt package
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({
        Name,
        email,
        password: hashedPassword
    });
    const token = await genrateJwt({email: newUser.email, id: newUser._id})
    newUser.token = token;
    await newUser.save();
    
    res.json({ status: httpStatusText.SUCCESS,msg: "The success of the registration process"});
};
export async function login(req, res, next)  {
    
    const { email, password } = req.body;

    if (!email && !password) {
        return res.status(400).json({ msg: "Email or Password is required" });
        
    }

    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(400).json({  msg: "User Not Found" });

    }

    const matchedPassword = await bcrypt.compare(password, user.password);

    if (user && matchedPassword) {
        const token = await genrateJwt({email: user.email, id: user._id})
        await User.updateOne({_id:user._id }, {$set:{token}})
        user.token = token
        return res.json({ status: httpStatusText.SUCCESS,  msg: "The success of the login process" });
    } else {
        
        return res.status(500).json({ error: "The password is incorrect" });

    }
};
export async function update(req, res)  {
    const userId = req.params.userId; 
    const updateUser = await User.updateOne({_id: userId}, {$set:{...req.body}});
    return res.status(200).json({status: httpStatusText.SUCCESS,  msg:{updateUser}})};
export async function deleteUser(req, res) {
        await User.deleteOne ({_id: req.params.userId});
        res.status(200).json({status: httpStatusText.SUCCESS,  msg: null});
    };
export async function forgotPassword(req, res, next) {
        const { error } = Joi.object({
            email: Joi.string().email().required()
        }).validate(req.body);
        if (error) {
            return res.status(400).send(error.details[0].message);
        }   
        const user = await User.findOne({email: req.body.email});
        if (!user) {
            return res.status(404).send( {msg:'User not found'});
        }
    const secret = process.env.JWT_SECRET_KEY + user.password;
    const token = jwt.sign({ email: user.email, id: user.id}, secret, {
        expiresIn: '60m'
    });
    const link = 
    `http://localhost:5000/api/users/resetpassword/${user._id}/${token}`;
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.ADMIN_EMAIL,
            pass: process.env.USER_PASS
        }
    });
    const mailOption = {
        from: process.env.ADMIN_EMAIL,
        to: user.email,
        subject: "reset password",
        text: `Please click on the following link to reset your password: ${link}`
    }
    transporter.sendMail(mailOption, (error , success) =>{
        if (error){
            console.log(error);
        }else{
            console.log("email send: " + success.response)
        }
    
    });
    res.send("link_send")
    }
export async function getResetPassword(req, res, next) {
    const user = await User.findById(req.params.userId);
    if (!user) {
        return res.status(404).send( {msg:'User not found'});

    }
const secret = process.env.JWT_SECRET_KEY + user.password;
try {
    jwt.verify(req.params.token, secret);
    res.status(200).send({email: user.email,  msg: 'reset password'});
} catch (error) {
    res.json(error.message).status(403)
}
;}
export async function resetPassword(req, res, next) {
    const user = await User.findById(req.params.userId);
    if (!user) {
        return res.status(404).send( {msg:'User not found'});

    }
const secret = process.env.JWT_SECRET_KEY + user.password;
try {
    jwt.verify(req.params.token, secret);
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(req.body.password, salt);
    user.password = req.body.password;
    await user.save();
    res.send({ msg:'success new password'});
} catch (error) {
    res.json(error.message).status(403)
}
}
export async function callback(req, res) {
        if (req.user) {
            res.status(200).json({
                error: false,
                msg: "successfully loged in",
                user: req.user,
            });
        } else {
            res.status(403).json({ error: true,  msg: "not authorized" });
        }
        }