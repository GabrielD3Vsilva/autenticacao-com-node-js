require('dotenv').config( );
const express = require('express');
const app = express( );
const ejs = require('ejs');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const PORT = 3000;
const User = require('./model/User');
const mongoose = require('mongoose');

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.lreepqy.mongodb.net/`)
.then(( ) => console.log('mongoDb atlas connected'))
.catch((err) => console.log(err));

app.set('view engine', 'ejs');
app.use(express.urlencoded());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json( ));
app.use(bodyParser.urlencoded({extended: false}));
app.use(express.json());

app.post('/auth/register', async (req, res) => {

    const {name, email, password, confirmPassword} = req.body;

    if(!name) {
        res.status(422).json({msg: 'o nome é obrigatório'});
    }

    if(!email) {
        res.status(422).json({msg: 'o email é obrigatório'});
    }

    if(!password) {
        res.status(422).json({msg: 'a senha é obrigatória'});
    }

    if(password != confirmPassword) {
        res.status(422).json({msg: 'as senhas não estão iguais'});
    }

    const userExists = User.findOne({email: email});

    if(userExists) {
        res.status(422).json({msg: 'por favor use outro email'})
    }

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: passwordHash
    });

    try {
        await user.save( );
    } catch (err) {
        res.status(500).json({msg: 'houve um erro de servidor'});
    }

});

app.post('/auth/login', async (req, res) => {
    const {email, password} = req.body;
    
    if(!email) {
        res.status(422).json({msg: 'o email é obrigatório'});
    };

    if(!password) {
        res.status(422).json({msg: 'a senha é obrigatória'});
    };

    const user = await User.findOne({email: email});

    if(!user) {
        res.status(404).json({msg: 'usuário não encontrado'});
    }

    const checkPassword = await bcrypt.compare(password,user.password);

    if(!checkPassword) {
        res.status(422).json({msg: 'senha incorreta'});
    };

    try {
        const secrete = process.env.SECRETE;

        const token = jwt.sign({id: user._id}, secrete);

        res.status(200).json({msg: 'autenticação feita com sucesso', token});

    } catch (err) {
        res.status(500).json({msg: 'erro no servidor'});
    }
    
})

app.get('/', (req, res) => {
    res.status(200).json({msg: 'sucesso ao conectar'});
});

app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;
    const user = await User.findById(id, '-password');

    if(!user) {
        return res.status(404).json({msg: 'usuário não encontrado'});
    };
    
    res.status(200).json({user});
});

function checkToken (req, res, next) {
    const authHeader = req.headers['authorization'];

    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({msg: "acesso negado"});
    };

    try {
        const secrete = process.env.SECRETE;
        jwt.verify(token, secrete);

        next( );

    } catch (err) {
        console.log(err);
    };

}



app.listen(PORT, ( ) => console.log('servidor rodando no localhost'));

