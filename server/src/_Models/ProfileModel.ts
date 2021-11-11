import { Schema, SchemaTypes, model } from "mongoose";

const ProfileSchmea = new Schema({
    user : {
        type : SchemaTypes.ObjectId,
        ref  : 'UserModel'
    },
    bio : {
        type : String,
    },
    profilePic : {
        type : String,
    },
    website : [{
        type : Object,
    }],
})




export default model("UserProfile", ProfileSchmea)