import mongoose from "mongoose";
import validator from 'validator';

const { Schema } = mongoose ;
const userModel = new Schema ({
    
    Name: {
        type: String,
        required: true,
        trim: true,
        minlength:[3,"Name must be longer than 3 character "],
        unique: true
       
    },
    email: {
        type:String,
        required:true,
        unique: true,
        validate: [validator.isEmail, 'failed must be a valid email address']
    },
    password: {
        type:String,
        required: true,
        trim: true,
        minlength:[8,"Name must be longer than 8 character "]
    },
    confirmPassword:{
        type:String,
        trim: true, 
        minlength:[8,"Name must be longer than 8 character "]
    },
    Verified:{
        type:Boolean,
        default:false
    }
    ,
    profilePhoto: {
        type: Object,
        default: {
            url: "https://cdn.pixabay.com/photo/2016/04/01/10/11/avatar-1299805_1280.png",
            publicId:null,
        }
    },
    token: {
        type: String
    }
},{timestamps: true})
export default mongoose.model('User', userModel);
