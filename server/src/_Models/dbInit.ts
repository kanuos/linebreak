import { connect } from "mongoose";


export default async function connectDB(dbURL : string) {
    try {
        if (!dbURL){
            throw new Error("Invalid DB connection string")
        }
        await connect(dbURL)
        return "Connected to DB "+ dbURL
    } 
    catch (error : any) {
        return error.message
    }
}


