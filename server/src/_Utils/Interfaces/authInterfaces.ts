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
