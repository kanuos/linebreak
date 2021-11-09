import Joi from "joi"

const CONSTRAINTS = {
    MIN_PASSWORD_LENGTH : 6,
    MIN_NAME_LENGTH : 3,
}

export const loginValidator = Joi.object().keys({
    email       : Joi.string().trim().email().required(),
    password    : Joi.string().trim().required().min(CONSTRAINTS.MIN_PASSWORD_LENGTH)
})

export const registerValidator = loginValidator.keys({
    name : Joi.string().trim().required().min(CONSTRAINTS.MIN_NAME_LENGTH)
})