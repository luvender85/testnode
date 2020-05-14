const Controller = require('./Controller');

class Cwe78Controller {
  constructor(Service) {
    this.service = Service;
  }

  async cwe78vid00001(request, response) {
    await Controller.handleRequest(request, response, this.service.cwe78vid00001);
  }

}

module.exports = Cwe78Controller;
