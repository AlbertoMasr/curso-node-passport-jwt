'use strict';

const { USER_TABLE } = require('./../models/user.model');

module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.addColumn(USER_TABLE, 'recovery_token', {
      type: Sequelize.STRING,
      allowNull: true,
      field: 'recovery_token'
    });
  },

  down: async (queryInterface) => {
    await queryInterface.removeColumn(USER_TABLE, 'recovery_token');
  }
};
