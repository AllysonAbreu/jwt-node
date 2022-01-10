const passport = require('passport')
const localStrategy = require('passport-local').Strategy
const bearerStrategy = require('passport-http-bearer').Strategy

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const Usuario = require('./usuarios-modelo')
const {InvalidArgumentError} = require('../erros')

const blacklist = require('../../redis/manipula-blacklist')



function verificaUsuario(usuario) {
  if(!usuario) {
    throw new InvalidArgumentError('Não existe usuário com esse e-mai')
  }
}
async function verificaTokenNaBlackList(token) {
  const tokenNaBlackList = await blacklist.contemToken(token)
  if(blacklist.contemToken(token)) {
    throw new jwt.JsonWebTokenError('Token inválido por logout')
  }
}

async function verificaSenha(senha, senhaHash) {
  const senhaValida = await bcrypt.compare(senha,senhaHash)

  if(!senhaValida) {
    throw new InvalidArgumentError('E-mail ou senha inválidos.')
  }
}

passport.use(
  new localStrategy({
    usernameField: 'email',
    passwordField: 'senha',
    session: false
  }, async (email, senha, done) => {
    try {
      const usuario = await Usuario.buscaPorEmail(email)
      verificaUsuario(usuario)
      await verificaSenha(senha, usuario.senhaHash)

      done(null, usuario)
    } catch (error) {
      done(error)
    }    
  })
)

passport.use(
  new bearerStrategy(
    async (token,done) => {
      try {
        await verificaTokenNaBlackList(token)
        const payload = jwt.verify(token, process.env.CHAVE_JWT)
        const usuario = await Usuario.buscaPorId(payload.id)
        done(null, usuario, {token:token})
      } catch (erro) {
        done(erro)        
      }
    }
  )
)