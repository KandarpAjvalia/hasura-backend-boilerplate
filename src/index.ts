import express from 'express'
import bodyParser from 'body-parser'
import userController from './controllers/user'

const app = express()
app.use(bodyParser.json())

const port = 3000

app.post('/register', userController.register)

app.post('/login', userController.login)

app.listen(port, () => {
	return console.log(`server is listening on ${port}`)
})
