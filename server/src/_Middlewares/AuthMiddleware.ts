import {Request, Response, NextFunction} from "express";
import { JwtPayload } from "jsonwebtoken";
import { checkValidity, clearTokensFromCookie, generateJWT, parseRequestCookie, setCookie } from "../_Services/authServices";

const JWT_ERRORS = ["TokenExpiredError", "JsonWebTokenError", "NotBeforeError"]


/**
 * @description
 * - This middleware prevents logged in users to visit onlyPublic routes viz login, register etc
 * - Request headers should contain cookies holding the access/refresh token pairs. 
 * - If valid pair exists or valid pair can be created from payload, prevent users from visiting route
 * - Else user not authorized ie logged in hence allowed to visit routes
 * @param req incoming http request 
 * @param res outgoing http response
 * @param next next middleware 
 * @method  public
 * @returns a http response or moves to the next middleware/route
 */
export function preventAuthorizedUsers(req: Request, res: Response, next: NextFunction) {
    try {
        const {at, rt} = parseRequestCookie(req);
        // if no cookies found
        if (!at || !rt) {
            clearTokensFromCookie(res)
            return next();   
        }
        // jwt present verify at & rt
        const isValidAT = checkValidity(at as string, "access"), isValidRT = checkValidity(rt as string, "refresh")

        // case 1: 
        // access token is valid and refresh token is valid
        // user is logged in => prevent user to visit route
        if (isValidAT.valid && isValidRT.valid) {
            req.body.loggedUser = isValidRT.payload
            throw new Error("already logged in")
        }
        // case 2:
        // refresh token is valid but access token is invalid
        // logged user not allowed to visit route
        if (!isValidAT.valid && (isValidRT.valid && Boolean(isValidRT.payload))) {
            const payload = {...isValidRT.payload as JwtPayload};
            req.body.loggedUser = isValidRT.payload
            delete payload.exp;
            delete payload.iat;
            const { access, refresh } = generateJWT(payload);
            setCookie(res, access, refresh)
            
            throw new Error("logged user not allowed to visit route")
        }
        // case 3:
        // refresh token is invalid
        // clear cookies
        // logged user not allowed to visit route
        if (!isValidRT.valid) {
            clearTokensFromCookie(res)
            return next()
         }
        // case 4:
        // both refresh and access tokens are valid
        // clear cookies and allow user to visit route
        if (!isValidRT.valid && !isValidAT.valid) {
            throw new Error("logged user cannot visit route")
        }
    } 
    catch (error : any) {
        if (JWT_ERRORS.includes(error.message)) {
            clearTokensFromCookie(res)
        }
        return res.status(300).json({
            message: error.message
        })
        
    }
} 


/**
 * @description
 * - This middleware prevents unauthorized/unauthenticated/malicious users visit onlyPrivate routes viz dashboard, profile etc
 * - Request headers should contain cookies holding the access/refresh token pairs. 
 * - If valid pair exists or valid pair can be created from payload, allow user to visit route
 * - Else user not authorized ie not logged in hence prevent user from visiting route
 * @param req incoming http request 
 * @param res outgoing http response
 * @param next next middleware 
 * @method  private
 * @returns a http response or moves to the next middleware/route
 */
 export function needsAuthorization(req: Request, res: Response, next: NextFunction) {
    try {
        const {at, rt} = parseRequestCookie(req);
        // if no cookies found
        if (!at || !rt) {
            throw new Error("Unauthorized")   
        }
        // jwt present verify at & rt
        const isValidAT = checkValidity(at as string, "access"), isValidRT = checkValidity(rt as string, "refresh")

        // case 1: 
        // refresh token is invalid
        // clear cookies and prevent user from visiting route
        if (!isValidRT.valid || !isValidRT.payload) {
            clearTokensFromCookie(res)
            throw new Error(isValidRT.payload as string)
        }
        // case 2: 
        // refresh token is valid
        // access token is invalid
        // generate new tokens and set cookies and allow user to visit
        if (!isValidAT.valid) {
            const payload = {...isValidRT.payload as JwtPayload};
            req.body.loggedUser = isValidRT.payload
            delete payload.exp;
            delete payload.iat;
            const {access, refresh} = generateJWT(payload)
            setCookie(res, access, refresh)
            return next()
        }        
        // case 3: 
        // refresh token is valid
        // access token is valid
        // allow user to visit route
        req.body.loggedUser = isValidRT.payload
        return next()
        
    } 
    catch (error : any) {
        clearTokensFromCookie(res)
        return res.status(401).json({
            message: error.message
        })
        
    }
} 

