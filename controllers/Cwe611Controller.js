const Controller = require('./Controller');

class Cwe611Controller {
  constructor(Service) {
    this.service = Service;
  }

  async cwe611vid00001(request, response) {
    await Controller.handleRequest(request, response, this.service.cwe611vid00001);
  }

}

module.exports = Cwe611Controller;
