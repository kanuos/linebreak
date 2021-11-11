import {Response, Request} from "express"
import { IJwtPayload, ILoginUser, IRegisterUser, IUser } from "../_Utils/Interfaces/authInterfaces";
import {hash, compare} from "bcryptjs"
import { sign, verify, JwtPayload } from "jsonwebtoken"
import UserModel from "../_Models/UserModel";

// constants and enums
const SALT = 12;
const TOKEN_TYPES = { access : "access", refresh: "refresh"}
const COOKIE_NAMES = {
    access  : "lb_at",
    refresh : "lb_rt"
}
const COOKIE_DURATION = {
    access : "10m",
    refresh : "7d"
}
const COOKIE_OPTIONS = {
    httpOnly : true,
    sameSite : true,
}

/**
 * @description
 * - Receives register user credentials [name, email, password]
 * - Checks if user email is available
 * - 
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
    
    const hashedPassword = await hashPassword(password as string);

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
 * @description
 * - Receives login user credentials [name, email, password]
 * - Checks if user email is available
 * - 
 * @param loginCredentials => login credentials email and password
 */
export async function handleLogin(loginCredentials : ILoginUser) : Promise<{_id : String, email: String}> {
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

    return {
        _id : existingUser._id,
        email : existingUser.email
    };

}



// ---------------------------------------------------------------------------------------


/**
 * @description
 * - Logs out a logged user
 * @method private
 * @param res 
 * @returns on success returns true
 */
export async function handleLogout(res: Response) : Promise<boolean> {
    await clearTokensFromCookie(res)
    return true;
}



// ---------------------------------------------------------------------------------------


/**
 * @description
 * - Checks Database to find a user with emailID 
 * @param email receives a valid email ID to check the database
 * @returns the user with email ID or undefined if user not found 
 */
async function getUserFromDB(email:String) : Promise<IUser | undefined> {
    return await UserModel.findOne({email})
}



// ---------------------------------------------------------------------------------------


/**
 * @description 
 * - Signs a new token using the corresponding type and payload and returns the new
 * - token string
 * @param payload payload to create the  token. contains {id, email}
 * @param type    either access or refresh allowed
 * @returns the signed token
 */
function signJWT(payload: IJwtPayload | string | JwtPayload, type : String) : String {
    const { ACCESS_SECRET, REFRESH_SECRET } = process.env;
    if (ACCESS_SECRET && REFRESH_SECRET) {
        switch(type.toLowerCase()) {
            case TOKEN_TYPES.access:
                return sign(payload, ACCESS_SECRET, {
                    expiresIn : COOKIE_DURATION.access,
                })
            case TOKEN_TYPES.refresh:
                return sign(payload, REFRESH_SECRET, {
                    expiresIn : COOKIE_DURATION.refresh,
                })
        }
    }
    throw new Error("JWT options missing")
}




// ---------------------------------------------------------------------------------------


/**
 * @description
 * - receives a token and type of token and returns the payload if valid/not expired
 * - else it throws an error message with appropriate message
 * @param token the string token representing jwt
 * @param type the type of jwt token. either " access " or " refresh " is allowed
 * @returns 
 */
export function verifyJWT(token: String, type : String) : JwtPayload | string {
    const { ACCESS_SECRET, REFRESH_SECRET } = process.env;
    if (ACCESS_SECRET && REFRESH_SECRET) {
        switch(type.toLowerCase()) {
            case TOKEN_TYPES.access:
                return verify(token as string, ACCESS_SECRET)    
            case TOKEN_TYPES.refresh:
                return verify(token as string, REFRESH_SECRET)    
        }
    }
    throw new Error("JWT options missing")
}


// ---------------------------------------------------------------------------------------
/**
 * @description
 * - receives the payload and returns the object comprising access and refresh tokens 
 * - created with the same payload
 * @param payload receives JWT payload ie {_id, email}
 * @returns object with access token and refresh token
 */
export function generateJWT(payload : IJwtPayload | string | JwtPayload) : {access : string, refresh : string} {
    const access = signJWT(payload, TOKEN_TYPES.access) as string,
        refresh  = signJWT(payload, TOKEN_TYPES.refresh) as string;
    
    return {
        access,
        refresh
    }
}



/**
 * @description
 * - clear the access and refresh tokens from the request cookie and in turn from the client's cookies
 * @param res express outgoing http response handler
 * @returns nothing
 */
export function clearTokensFromCookie(res: Response) : void {
    res.clearCookie(COOKIE_NAMES.access, COOKIE_OPTIONS)
    res.clearCookie(COOKIE_NAMES.refresh, COOKIE_OPTIONS)
}



/**
 * @description
 * - set the response tokens with access and refresh tokens and in turn adds to client's cookies
 * @param res express http outgoing response
 * @param at access token string (new)
 * @param rt refresh token string (new)
 */
export function setCookie(res: Response, at: string, rt: string) {
    res.cookie(COOKIE_NAMES.access, at, COOKIE_OPTIONS)
    res.cookie(COOKIE_NAMES.refresh, rt, COOKIE_OPTIONS)
}



/**
 * @description
 * - parse the header cookies from the incoming http request and returns the access and refresh tokens
 * - passed in the cookie
 * @param req incoming http request handler by express
 * @returns access token and refresh token 
 */
export function parseRequestCookie(req: Request) : {at: string | undefined, rt : string | undefined} {
    const cookie = req.headers.cookie;
    if (!cookie) {
        return {
            at: undefined,
            rt: undefined
        }
    }
    const cookies : string[] = cookie.split(';');
    let at, rt;
    cookies.forEach((cookie : String) : void => {
        if (cookie.trim().startsWith(COOKIE_NAMES.access)) {
            at = cookie.split("=")[1]
            return
        }
        if (cookie.trim().startsWith(COOKIE_NAMES.refresh)) {
            rt = cookie.split("=")[1]
            return
        }
    })

    return {
        at, rt
    }
}



/**
 * @description
 * - Receives the token and type of token and evaluates whether the token is valid or not
 * - if the token is valid the payload is sent along with the true status
 * - else the false status is sent with an undefined value
 * @param token a string token representing jwt
 * @param type the type of token wither " access " or " refresh "
 * @returns object with a valid boolean field and on valid fields attach the singing payload
 */
export function checkValidity(token : string, type : string) : {valid : boolean, payload : JwtPayload | string | undefined} {
    try {
        const payload = verifyJWT(token, type)
        return {
            valid : Boolean(payload),
            payload
        }
    } 
    catch (error : any) {
        return {
            valid : false,
            payload : error.name
        }
     }
}



export async function hashPassword(password : string) : Promise<string>{
    return await hash(password, SALT);
}