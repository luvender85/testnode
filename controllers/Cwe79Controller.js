const Controller = require('./Controller');

class Cwe79Controller {
  constructor(Service) {
    this.service = Service;
  }

  async cwe79vid00001(request, response) {
    await Controller.handleRequest(request, response, this.service.cwe79vid00001);
  }

}

module.exports = Cwe79Controller;
