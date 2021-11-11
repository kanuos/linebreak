import Joi from "joi";

export const passwordResetValidator = Joi.object({
    password : Joi.string().trim().required().min(6)
})