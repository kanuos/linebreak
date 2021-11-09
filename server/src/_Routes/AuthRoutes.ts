import { Router } from "express";
import authController from "../_Contoller/authController";
const auth = Router()


/**
 * 
 * @description
 * - Handles the incoming request to login an existing user
 * 
 * - Only JSON is sent
 * 
 * - On SUCCESS returns the logged in user and creates tokens for authorization
 * - On FAILURE returns corresponding error messages
 * - URL : /auth/login
 * 
 * - POST authorization users are not allowed to visit page
 * 
 * @access public
 * @method  POST
 * @param email     User's email ID that was used at registration
 * @param password  User's plain text password which was used to registration
 */

auth.post("/login", authController.login)

/**
 * @description
 * - Handles the incoming request to register a new user
 * 
 * - Only JSON is sent
 * 
 * - On SUCCESS returns the new user's id
 * - On FAILURE returns corresponding error messages
 * - URL : /auth/register
 * 
 * - POST authorization users are not allowed to visit page
 * @access public
 * @method  POST
 * @param name     User's email ID that was used at registration
 * @param email     User's email ID that was used at registration
 * @param password  User's plain text password which was used to registration
 */

auth.post("/register", authController.register)




export default auth;