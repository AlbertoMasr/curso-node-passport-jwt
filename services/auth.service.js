const boom = require('@hapi/boom')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");

const { config } = require('../config/config');

const UserServie = require('./user.service');
const service = new UserServie();

class AuthService {

  async getUser(email, password) {
    const user = await service.findByEmail(email);
    if(!user) {
      throw boom.unauthorized();
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if(!isMatch) {
      throw boom.unauthorized();
    }
    delete user.getDataValue.password;
    return user;
  }

  signToken(user){
    const payload = {
      sub: user.id,
      role: user.role,
    }
    const token = jwt.sign(payload, config.jwtSecret)
    return {
      user,
      token
    }
  }

  async sendRecovery(email) {
    const user = await service.findByEmail(email);
    if(!user) {
      throw boom.unauthorized();
    }

    const payload = { sub: user.id };
    const token = jwt.sign(payload, config.jwtSecret, { expiresIn: '15m' })
    const link = `http://frontend/recovery?token=${token}`;
    await service.update(user.id, { recoveryToken: token })
    const mail = {
      from: config.smtpEmail,
      to: `${user.email}`,
      subject: "Email para recuperar contrasena",
      html: `<b>Ingresa a este link => ${link}</b>`,
    };

    const response = await this.sendMail(mail);
    return response;

  }

  async changePassword(token, newPassword) {
    try {
      const payload = jwt.verify(token, config.jwtSecret);
      const user = await service.findOne(payload.sub);
      if(user.recoveryToken !== token) {
        throw boom.unauthorized();
      }
      const hash = await bcrypt.hash(newPassword, 10);
      await service.update(user.id, { password: hash, recoveryToken: null });
      return { message: 'Password changed' };
    } catch (error) {
      throw boom.unauthorized();
    }
  }

  async sendMail(infoMail){
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: config.smtpEmail,
        pass: config.smtpPassword,
      },
    });

    await transporter.sendMail(infoMail);
    return { message: 'Mail sent' }
  }

}

module.exports = AuthService;
