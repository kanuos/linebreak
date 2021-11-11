import UserModel from "../_Models/UserModel";
import { hashPassword } from "./authServices";

export async function changePassword(userID : string, newPassword : string) : Promise<boolean> {
    try {
        const hashedPassword = await hashPassword(newPassword);
        await UserModel.findByIdAndUpdate(userID, 
            {
                $set : {
                    password : hashedPassword
                }
            }, 
            {
                new : true
            }
        )    
        return true;
    } 
    catch (error : any) {
        return false;
    }

}