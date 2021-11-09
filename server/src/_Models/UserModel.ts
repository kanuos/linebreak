import { model, Schema } from "mongoose";

const UserSchema = new Schema({
    name : {
        type : String,
        required: true,
        minlength : 3
    },
    email : {
        type : String,
        required: true,
        unique: true,
        minlength : 5
    },
    password : {
        type : String,
        required: true,
        unique: true,
        minlength: 6,
    },
})



export default model("UserModel", UserSchema)