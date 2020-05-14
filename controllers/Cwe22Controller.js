const Controller = require('./Controller');

class Cwe22Controller {
  constructor(Service) {
    this.service = Service;
  }

  async cwe22vid00001(request, response) {
    await Controller.handleRequest(request, response, this.service.cwe22vid00001);
  }

}

module.exports = Cwe22Controller;
