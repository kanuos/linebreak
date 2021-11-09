// import libraries, functions and more
import {config} from "dotenv"
import express , { Application } from "express";
import AuthRouteHandler from "./_Routes/AuthRoutes"
import dbConfig from "./_Models/dbInit";

// intialized the environment config to read process.env  
// destructure the environment variables
config();
const {PORT, MONGO_URL} = process.env;


// the express application is initialized
// request parsing middlewares
const app : Application = express();
app.use(express.json())
app.use(express.urlencoded({ extended: false }))


// connecting to DB
if (MONGO_URL){
    dbConfig(MONGO_URL as string)
        .then(console.log)
        .catch(() => process.exit(1))
}
else {
    process.exit(1)
}

// route middlewares
app.use("/auth", AuthRouteHandler)


// app/server listening to incoming http requests on PORT
app.listen(PORT ?? 8000 , () => console.log(`Server running on PORT ${PORT}`))   