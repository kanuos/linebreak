interface User {
    email : String, password : String, name : String, _id : Number
}

import { ILoginUser, IRegisterUser } from "../_Utils/Interfaces/authInterfaces";
import {hash, compare} from "bcryptjs"
import UserModel from "../_Models/UserModel";

const SALT = 12;

/**
 * 
 * @param registerCredentials => register credentials name, email and password
 */
export async function handleRegister(
    registerCredentials : IRegisterUser) 
    : Promise<boolean> {
    // receives email and password as parameters
    const {email, password, name} = registerCredentials;

    // check if user with email exists in database
    const existingUser = await getUserFromDB(email)
    if (existingUser) {
        throw new Error("Email already taken")
    }
    
    const hashedPassword = await hash(password as string, SALT);

    const newUser = {
        email,
        password : hashedPassword,
        name
    } 

    await UserModel.create(newUser);
    // if credentials are valid generate jwts
    return true
}

// ---------------------------------------------------------------------------------------


/**
 * 
 * @param loginCredentials => login credentials email and password
 */
export async function handleLogin(loginCredentials : ILoginUser) : Promise<boolean> {
    // receives email and password as parameters
    const {email, password} = loginCredentials;

    // check if user with email exists in database
    const existingUser = await getUserFromDB(email)
    if (!existingUser) {
        throw new Error("User doesn't exist")
    }

    // if user exists compare the hashedPassword with the credential password
    const isValidUser = await compare(password as string, existingUser.password as string);

    if (!isValidUser) {
        throw new Error("Invalid Credentials")
    }

    return true;

}


async function getUserFromDB(email:String) : Promise<User | undefined> {
    return await UserModel.findOne({email})
}