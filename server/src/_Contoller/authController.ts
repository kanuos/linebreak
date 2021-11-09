import { Request, Response } from "express";
import { handleLogin, handleRegister } from "../_Services/authServices";
import {IAuthResponse} from "../_Utils/Interfaces/authInterfaces"
import { loginValidator, registerValidator } from "../_Utils/Validator/authValidator";



/**
 * @description
 * - Handles incoming register request.
 * - Checks for body's pre-defined formation
 * - validates incoming credentials constraints
 * - performs register services upon successful validation
 * - ON SUCCESS 
 *      returns success message
 * - ON FAILURE
 *      returns error object
 * @param email
 *      - new user's valid email ID
 * @param password
 *      - plain text password following constraints 
 * @param name
 *      - new user's name
 *  
 * @returns 
 *      - response object along with a valid HTTP code
 */
async function registerController(req: Request, res : Response) {
    let responseObject : IAuthResponse, status = 201;
    try {
        const {value, error} = registerValidator.validate(req.body);
        
        // if request body is malformed 
        if (error) {
            throw new Error(error.details[0].message)
        } 

        // handle login request using handleLogin service
        const payload = await handleRegister(value);
        responseObject = {
            error : false,
            message : 'Registered successfully',
            payload
        }
        return res.status(status).json(responseObject)
    } 
    catch (error : any) {
        responseObject = {
            error : true,
            message : error.message,
            payload : null
        }
        status = 400;
        return res.status(status).json(responseObject)
    }
}


/**
 * @description
 * - Handles incoming login request.
 * - Checks for body's pre-defined formation
 * - validates incoming credentials constraints
 * - performs login services upon successful validation
 * - ON SUCCESS 
 *      returns login credentials (JWT) as well as payload
 * - ON FAILURE
 *      returns error object
 * @param email
 *      - existing user's valid email ID
 * @param password
 *      - plain text password following constraints
 *  
 * @returns 
 *      - response object along with a valid HTTP code
 */
async function loginController(req: Request, res : Response) {
    let responseObject : IAuthResponse, status = 200;
    try {
        const {value, error} = loginValidator.validate(req.body);
        
        // if request body is malformed 
        if (error) {
            throw new Error(error.details[0].message)
        } 

        // handle login request using handleLogin service
        const payload = await handleLogin(value)
        responseObject = {
            error : false,
            message : 'Logged in successfully',
            payload
        }
        return res.status(status).json(responseObject)
    } 
    catch (error : any) {
        responseObject = {
            error : true,
            message : error.message,
            payload : null
        }
        status = 400;
        return res.status(status).json(responseObject)
    }
}


export default {
    login : loginController,
    register : registerController
}