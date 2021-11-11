import {Request, Response} from "express";
import ProfileModel from "../_Models/ProfileModel";
import { changePassword } from "../_Services/profileServices";
import { passwordResetValidator } from "../_Utils/Validator/profileValidator";


/**
 * 
 * @param req 
 * @param res 
 */
async function handleGetProfileRequest(req: Request, res: Response) {
    try {
        const {loggedUser} = req.body;
        const userProfile = await ProfileModel.findOne({
            user : loggedUser._id
        });
        return res.json({
            profile : userProfile
        })         
    } 
    catch (error: any) {
        
    }
}


async function handleChangePassword(req: Request, res: Response) {
    try {
        const {password, loggedUser} = req.body;
        // validate the incoming password field with joi
        const {value, error} = passwordResetValidator.validate({password});

        // on error send the error message as response
        if (error) {
            throw new Error(error.details[0].message)
        }
        // change the password and on success send response
        // on failure send error message
        const success = await changePassword(loggedUser._id, value.password);
        if (!success) {
            throw new Error("Password couldn't be changed")
        }
        return res.json({
            error: false,
            message: "password changed",
        })
    } 
    catch (error : any) {
        return res.json({
            error: true,
            message : error.message
        })
    }
}


export default {
    profile : handleGetProfileRequest,
    reset : handleChangePassword
}