import express from 'express'
import {findUserByEmail, getGraphQL, getRequestData, validateEmail} from '../utils'
import bcrypt from 'bcrypt'
import axios from 'axios'
import {adminConfig} from '../config/adminConfig'

const register = async (req: express.Request, res: express.Response) => {
	const {
		email,
		password
	} = req.body

	if (email === '' || password === '') {
		res.json({
			status: 'error',
			message: 'Enter Email and Password'
		})
		return
	}

	const isEmailValid = validateEmail(email)

	if (!isEmailValid) {
		res.json({
			status: 'error',
			message: 'Invalid Email'
		})
		return
	}

	let userExists = null

	try {
		userExists = await findUserByEmail(email)

	} catch (err) {
		console.error(err)
		res.json({
			status: 'error',
			message: 'Server Error'
		})
		return
	}

	let registerUserResponse = null
	if (!userExists) {
		try {
			const registerUser = await getGraphQL('mutation', 'registerUser')

			const hashedPassword = await bcrypt.hash(password, 10)

			const data = getRequestData(registerUser, {
				email,
				password: hashedPassword
			})
			registerUserResponse = await axios.post('http://localhost:8080/v1/graphql', data, adminConfig)
			console.log(JSON.stringify(registerUserResponse.data, null, 2))

		} catch (err) {
			console.error(err)
			res.json({
				status: 'error',
				message: 'Server Error'
			})
			return
		}
	} else {
		res.json({
			status: 'error',
			message: 'Please Login'
		})
		return
	}

	res.json(registerUserResponse.data)
}

const login = async (req: express.Request, res: express.Response) => {
	const {
		email,
		password
	} = req.body

	let userData = null

	try {
		userData = await findUserByEmail(email)

	} catch (err) {
		console.error(err)
	}

	if (!userData) {
		res.json({
			status: 'error',
			message: 'Invalid Email or Password'
		})
		return
	}

	const hashedPassword = userData.data.user[0].password

	const passwordsMatch = await bcrypt.compare(password, hashedPassword)

	if (!passwordsMatch) {
		res.json({
			status: 'error',
			message: 'Invalid Email or Password'
		})
		return
	}

	res.json(userData)
}

export default {register, login}

