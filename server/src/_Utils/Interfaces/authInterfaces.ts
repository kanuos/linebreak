export interface IAuthResponse {
    message : String,
    error : Boolean,
    payload : Object | null | String
}

export interface ILoginUser {
    email    : String,
    password : String
}


export interface IRegisterUser extends ILoginUser{
    name : String,
}


export interface IJwtPayload {
    _id     : String | Number,
    email   : String,
    exp?    : Number
}

export interface IUser {
    email : String, password : String, name : String, _id : String
}
